import time
from threading import Thread
from .logger import *


class CheckedProcessException(Exception):
    pass

def get_name_from_cmd(cmd):
    return cmd.split()[0]

def monitor_wait(event, seconds):
    if event is None:
        if self.error_event.wait(seconds):
            return False
    else:
        time.sleep(seconds)
    return True

CHECK_CALL_INTERVAL= .2

def monitor_process(process,
                    min_duration = None, max_duration = None,
                    chacked_rtn = None, log_end=False,
                    check_interval = CHECK_CALL_INTERVAL):
    process.start()
    start_time = time.time()
    rtn_code = process.poll(checked_rtn)
    while not process.exited:
        duration = time.time() - start

        if max_duration is not None and duration > max_duration:
            log_error("Command \"", process.name, "\" executed for longer than ",
                      max_duration, " seconds")
            if process.STOPPABLE:
                process.force_stop()
            raise CheckedProcessException(name)

        if max_duration is not None:
            sleep_duration = min(max_duration - duration, check_interval)
            sleep_duration = max(sleep_duration, .05)
        else:
            sleep_duration = check_interval

        process.wait(sleep_duration)

        rtn_code = process.poll(checked_rtn)

    if checked_rtn is not None and rtn_code != checked_rtn:
        log_error("Command:\n\t%s\nReturned: %d\nExpected: %d\n" %
                      (process.name, rtn_code, checked_rtn),
                      "If this is not an error, add `checked_rtn: null` to command")
        raise CheckedProcessException(name)

    if min_duration is not None and duration < min_duration:
        log_error("Command \"", process.name, "\" executed for ", duration,
                  "seconds; expected: ", min_duration)
        raise CheckedProcessException(name)

    if log_end:
        log("Command ", name, " executed for ", duration, " seconds")

def launch_process_monitor(daemon, *args, **kwargs):
    t = Thread(target = ssh_call, args=(cmd, ssh_cfg, addr, stop_cmd), kwargs=kwargs)
    t.daemon = daemon
    t.start()
    return t
