#!/usr/bin/env python

#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import print_function
import logging
from optparse import OptionParser
import os
import re
import shutil
import subprocess
import sys
import tempfile
from threading import Thread, Lock
import time
import uuid
if sys.version < '3':
    import Queue
else:
    import queue as Queue
from collections import deque
from distutils.version import LooseVersion
from multiprocessing import Manager


# Append `SPARK_HOME/dev` to the Python path so that we can import the sparktestsupport module
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../dev/"))


from sparktestsupport import SPARK_HOME  # noqa (suppress pep8 warnings)
from sparktestsupport.shellutils import which, subprocess_check_output  # noqa
from sparktestsupport.modules import all_modules, pyspark_sql  # noqa


python_modules = dict((m.name, m) for m in all_modules if m.python_test_goals if m.name != 'root')


def print_red(text):
    print('\033[31m' + text + '\033[0m')


SKIPPED_TESTS = Manager().dict()
LOG_FILE = os.path.join(SPARK_HOME, "python/unit-tests.log")
FAILURE_REPORTING_LOCK = Lock()
LOGGER = logging.getLogger()

# Find out where the assembly jars are located.
# Later, add back 2.12 to this list:
# for scala in ["2.11", "2.12"]:
for scala in ["2.11"]:
    build_dir = os.path.join(SPARK_HOME, "assembly", "target", "scala-" + scala)
    if os.path.isdir(build_dir):
        SPARK_DIST_CLASSPATH = os.path.join(build_dir, "jars", "*")
        break
else:
    raise Exception("Cannot find assembly build directory, please build Spark first.")


def run_individual_python_test(target_dir, test_name, pyspark_python, failed_tests_deque):
    env = dict(os.environ)
    env.update({
        'SPARK_DIST_CLASSPATH': SPARK_DIST_CLASSPATH,
        'SPARK_TESTING': '1',
        'SPARK_PREPEND_CLASSES': '1',
        'PYSPARK_PYTHON': which(pyspark_python),
        'PYSPARK_DRIVER_PYTHON': which(pyspark_python)
    })

    # Create a unique temp directory under 'target/' for each run. The TMPDIR variable is
    # recognized by the tempfile module to override the default system temp directory.
    tmp_dir = os.path.join(target_dir, str(uuid.uuid4()))
    while os.path.isdir(tmp_dir):
        tmp_dir = os.path.join(target_dir, str(uuid.uuid4()))
    os.mkdir(tmp_dir)
    env["TMPDIR"] = tmp_dir

    # Also override the JVM's temp directory by setting driver and executor options.
    spark_args = [
        "--conf", "spark.driver.extraJavaOptions=-Djava.io.tmpdir={0}".format(tmp_dir),
        "--conf", "spark.executor.extraJavaOptions=-Djava.io.tmpdir={0}".format(tmp_dir),
        "pyspark-shell"
    ]
    env["PYSPARK_SUBMIT_ARGS"] = " ".join(spark_args)

    LOGGER.info("Starting test(%s): %s", pyspark_python, test_name)
    start_time = time.time()
    # This line must come before the try block, file shouldn't be closed before 'worker' is done
    per_test_output = tempfile.TemporaryFile()
    try:
        process = subprocess.Popen(
            [os.path.join(SPARK_HOME, "bin/pyspark"), test_name],
            # bufsize must be 0 (unbuffered), 1 (line buffered) doesn't seem to work
            stderr=subprocess.STDOUT, stdout=subprocess.PIPE, env=env, bufsize=0,
            universal_newlines=True)

        def consume_log(output):
            for line in process.stdout:
                print("({}) {} - {}".format(pyspark_python, test_name, line), end=b'')
                print(line, file=output, end=b'')

        worker = Thread(target=consume_log, args=(per_test_output,))
        worker.start()  # This is essential as we need to consume the stdout pipe
        retcode = process.wait()
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except:
        LOGGER.exception("Got exception while running %s with %s", test_name, pyspark_python)
        # Here, we use os._exit() instead of sys.exit() in order to force Python to exit even if
        # this code is invoked from a thread other than the main thread.
        os._exit(-1)
    duration = time.time() - start_time
    worker.join()  # Wait on the thread that consumed the output
    # If it failed, append output to LOG_FILE, add to failed tests and carry on
    if retcode != 0:
        try:
            with FAILURE_REPORTING_LOCK:
                with open(LOG_FILE, 'ab') as log_file:
                    per_test_output.seek(0)
                    log_file.writelines(per_test_output)
                per_test_output.seek(0)
                for line in per_test_output:
                    decoded_line = line.decode()
                    if not re.match('[0-9]+', decoded_line):
                        print(decoded_line, end='')
                per_test_output.close()
        except:
            LOGGER.exception("Got an exception while trying to print failed test output")
        finally:
            print_red("\nHad test failures in %s with %s; see logs." % (test_name, pyspark_python))
            failed_tests_deque.append((test_name, pyspark_python))
    else:
        skipped_counts = 0
        try:
            per_test_output.seek(0)
            # Here expects skipped test output from unittest when verbosity level is
            # 2 (or --verbose option is enabled).
            decoded_lines = map(lambda line: line.decode(), iter(per_test_output))
            skipped_tests = list(filter(
                lambda line: re.search(r'test_.* \(pyspark\..*\) ... skipped ', line),
                decoded_lines))
            skipped_counts = len(skipped_tests)
            if skipped_counts > 0:
                key = (pyspark_python, test_name)
                SKIPPED_TESTS[key] = skipped_tests
            per_test_output.close()
        except:
            import traceback
            print_red("\nGot an exception while trying to store "
                      "skipped test output:\n%s" % traceback.format_exc())
            # Here, we use os._exit() instead of sys.exit() in order to force Python to exit even if
            # this code is invoked from a thread other than the main thread.
            os._exit(-1)
        if skipped_counts != 0:
            LOGGER.info(
                "Finished test(%s): %s (%is) ... %s tests were skipped", pyspark_python, test_name,
                duration, skipped_counts)
        else:
            LOGGER.info(
                "Finished test(%s): %s (%is)", pyspark_python, test_name, duration)


def get_default_python_executables():
    python_execs = [x for x in ["python2.7", "python3.4", "pypy"] if which(x)]
    if "python2.7" not in python_execs:
        LOGGER.warning("Not testing against `python2.7` because it could not be found; falling"
                       " back to `python` instead")
        python_execs.insert(0, "python")
    return python_execs


def parse_opts():
    parser = OptionParser(
        prog="run-tests"
    )
    parser.add_option(
        "--python-executables", type="string", default=','.join(get_default_python_executables()),
        help="A comma-separated list of Python executables to test against (default: %default)"
    )
    parser.add_option(
        "--modules", type="string",
        default=",".join(sorted(python_modules.keys())),
        help="A comma-separated list of Python modules to test (default: %default)"
    )
    parser.add_option(
        "-p", "--parallelism", type="int", default=4,
        help="The number of suites to test in parallel (default %default)"
    )
    parser.add_option(
        "--verbose", action="store_true",
        help="Enable additional debug logging"
    )

    (opts, args) = parser.parse_args()
    if args:
        parser.error("Unsupported arguments: %s" % ' '.join(args))
    if opts.parallelism < 1:
        parser.error("Parallelism cannot be less than 1")
    return opts


def _check_coverage(python_exec):
    # Make sure if coverage is installed.
    try:
        subprocess_check_output(
            [python_exec, "-c", "import coverage"],
            stderr=open(os.devnull, 'w'))
    except:
        print_red("Coverage is not installed in Python executable '%s' "
                  "but 'COVERAGE_PROCESS_START' environment variable is set, "
                  "exiting." % python_exec)
        sys.exit(-1)


def main():
    opts = parse_opts()
    if (opts.verbose):
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logging.basicConfig(stream=sys.stdout, level=log_level, format="%(message)s")
    LOGGER.info("Running PySpark tests. Output is in %s", LOG_FILE)
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    python_execs = opts.python_executables.split(',')
    modules_to_test = []
    for module_name in opts.modules.split(','):
        if module_name in python_modules:
            modules_to_test.append(python_modules[module_name])
        else:
            print("Error: unrecognized module '%s'. Supported modules: %s" %
                  (module_name, ", ".join(python_modules)))
            sys.exit(-1)
    LOGGER.info("Will test against the following Python executables: %s", python_execs)
    LOGGER.info("Will test the following Python modules: %s", [x.name for x in modules_to_test])

    task_queue = Queue.PriorityQueue()
    for python_exec in python_execs:
        # Check if the python executable has coverage installed when 'COVERAGE_PROCESS_START'
        # environmental variable is set.
        if "COVERAGE_PROCESS_START" in os.environ:
            _check_coverage(python_exec)

        python_implementation = subprocess_check_output(
            [python_exec, "-c", "import platform; print(platform.python_implementation())"],
            universal_newlines=True).strip()
        LOGGER.debug("%s python_implementation is %s", python_exec, python_implementation)
        LOGGER.debug("%s version is: %s", python_exec, subprocess_check_output(
            [python_exec, "--version"], stderr=subprocess.STDOUT, universal_newlines=True).strip())
        for module in modules_to_test:
            if python_implementation not in module.blacklisted_python_implementations:
                for test_goal in module.python_test_goals:
                    if test_goal in ('pyspark.streaming.tests', 'pyspark.mllib.tests',
                                     'pyspark.tests', 'pyspark.sql.tests'):
                        priority = 0
                    else:
                        priority = 100
                    task_queue.put((priority, (python_exec, test_goal)))

    # Create the target directory before starting tasks to avoid races.
    target_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'target'))
    if not os.path.isdir(target_dir):
        os.mkdir(target_dir)

    def process_queue(task_queue, failed_tests_deque):
        while True:
            try:
                (priority, (python_exec, test_goal)) = task_queue.get_nowait()
            except Queue.Empty:
                break
            try:
                run_individual_python_test(target_dir, test_goal, python_exec, failed_tests_deque)
            finally:
                task_queue.task_done()

    # Using a deque because it supports thread-safe appends
    failed_tests_deque = deque()
    start_time = time.time()
    for _ in range(opts.parallelism):
        worker = Thread(target=process_queue, args=(task_queue, failed_tests_deque))
        worker.daemon = True
        worker.start()
    try:
        task_queue.join()
    except (KeyboardInterrupt, SystemExit):
        print_red("Exiting due to interrupt")
        sys.exit(-1)
    total_duration = time.time() - start_time
    if len(failed_tests_deque) != 0:
        LOGGER.error("%i tests failed after %i seconds:", len(failed_tests_deque), total_duration)
        for test_and_python in failed_tests_deque:
            print_red("\nHad test failures in %s with %s; see logs." % test_and_python)
        sys.exit(-1)

    LOGGER.info("Tests passed in %i seconds", total_duration)

    for key, lines in sorted(SKIPPED_TESTS.items()):
        pyspark_python, test_name = key
        LOGGER.info("\nSkipped tests in %s with %s:" % (test_name, pyspark_python))
        for line in lines:
            LOGGER.info("    %s" % line.rstrip())


if __name__ == "__main__":
    main()
