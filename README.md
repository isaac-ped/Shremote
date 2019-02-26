# Shremote!

Execute commands remotely over SSH!

`Usage: python shremote.py <config.yml> <label> [--test] [--export <loc>] [--stop-only]`

* `--test`: Runs through each command as fast as possible to ensure proper formatting
* `--export`: Copies all log files to <loc> at end of test
* `--stop-only`: Stops all programs present in the config

I think the program is easier to understand from examples, so be sure to look at the config
and sample yml files.

## Configuration

The following is a sample configuration file. Details of each section are laid out below:
```yaml
# Declare the default ssh parameters
ssh:
    user: isaac-ped
    key: '~/.ssh/id_rsa'
    port: 22

# These commands are run on the local machine before test begins
# Use it to generate files used during testing
init_cmds:
    generate_client_file: 'python make_client_file.py --output {0.files.client_file.src}'

# Copy files from the local machine to remote hosts
files:
    client_file:
        src: 'my_test_file.dat'
        dst: '{0.programs.log_dir}/my_test_file.dat'
        host: clients

# Hosts are machines used in the experiments
hosts:
    # The can consist of a single machine:
    server:
        addr: domain1.edu
    # Or a group of machines:
    clients:
        - addr: domain2.edu
        - addr: domain3.edu
          ssh: # And can provide custom ssh parameters
            user: domain3_user
            key: domain3_key
            port: 22

# Not necessary, but can declare parameters here referencable from anywhere
globals:
    experiment_length: 60
    my_param: 'parameter_value'

# Next, define the programs that will be executed during the test
programs:
    # Programs all write logs to this base directory
    log_dir: ~/logs/{0.label}/

    # This program runs on the 'server' host
    setup_exp:
        host: server
        start: 'cd /path/to/script && ./do_something {param_1} {other_param}'
        stop: pkill do_something
        check_rtn: 0 # Ensure the processs returns 0
        log: # Automatically log all stdout and stderr to these files
            out: setup_stdout.txt
            err: setup_stderr.txt

    run_exp:
        host: clients
        start: 'cd /path/to/script && ./run_experiment {param_2} {duration}'
        stop: pkill run_experiment
        log: # Put logs in this subdirectory
            dir: experiment
            out: experiment_{i}_stdout.txt # Label logs with the experiment number
            err: experiment_{i}_stderr.txt

# Finally, define the timecourse and parameters of execution
commands:

    setup_exp:
        begin: -20 # Start 20 second before main experiment
        param_1: '{0.args.setup_param}' # Get this parameter from startup args
        other_param: '{0.globals.my_param}' # Get this one from global definitions

    # Run the experiment two times, with a 60 second pause between
    run_exp:
        - begin: 0
          duration: '{0.globals.experiment_length}' # Run for 60 seconds
          enforce_duration: True # Make sure that it doesn't end early
          param_2: '{0.args.exp_param}' # Get this from startup args

        - begin: '{0.globals.experiment_length} * 2' # Math possible!
          duration: '{0.globals.experiment_length}'
          param_2: '{0.args.exp_param}'
```


The programs, commands, logs, and timing are all defined in a central yml file.

For ease of reproducing, a special `!include <file>` command is added to the yml parser.
This allows portions of the config used across multiple files to be kept in a centralized location.

Throughout the config file, different parts of the config can be referenced using python's
string formatting syntax. The complete config is passed as the first argument to all formatting,
such that if one defines `foo: bar` at the top level of the config, `qux: {0.foo}` will change to
`qux: bar` after substitution.

Certain special variables are also available via substitution, such as `{0.label}`, which is
the label passed in at runtime. Different parts of the config have their own variables
(described below).

The required parts of the config file are:

### ssh:

The default SSH configuration by which to connect to the hosts. **Must** define:
* `user`: The username with which to connect
* `key`: A path to an private SSH-key
* `port`: The port over which to connect

### hosts:

A list of hosts on which programs can be run. Each host defines:
* `addr`: The hostname or IP address at which the host can be reached
* `ssh`: Optional SSH config (as above) which overrides the default config

**Note:** A "host" may actually be a *list* of hosts, in which case commands that specifies
that host will be run on all specified machines

### logs:

A dictionary mapping program names to log files. Log files will be rsynced locally at the end
of the session.

This section **must** define:
* `dir`: The directory **on each host** to which log files will be recorded.
Will be created if it does not exist.

In addition, a log file may be specified for each program (defined below). Each log entry
can specify:
* `dir`: A subdirectory into which logs will be placed
* `out`: Redirects stdout to this file
* `err`: Redirects stderr to this file
* `log`: Can be passed (fully formatted) to the program's execution string

Each log has available the variable:
* `{i}`: If a program is run multiple times, or on multiple hosts, this index will distinguish log
files from one another. (Behavior undefined if `{i}` is not used and multiple program instances
are started)
* `{host}`: Will substitute the address of the host on which the command is being run

### programs:

This section defines a dictionary mapping each program name to the command used to execute that
program.

Each program has the following required fields:
* `host`: The name of the host (as defined in `hosts:` above) on which the program should be run.
**Note:** as stated above, a "host" may be a list of hosts on which the program will run
simultaneously.
* `start`: (Not strictly required if `stop` is defined) The command used to start the program. In addition to
referencing global config variables (with `{0.field}`), it can also reference:
  * `{var}` where `var:` is defined in the instance of the program (defined below).
  * `{log}` which is substituted for the log filename as defined in the `logs:` config portion

The following optional fields:
* `stop`: The command used to stop execution of the program. Used if `duration` is present
in the command arguments, or `--stop-only` is passed to the python program as a whole.
* `fg`: If `True`, will execute the program in the foreground (and block execution till completion)
rather than spawning a thread. Should only be used for short-lived or blocking commands.
* `check_rtn`: If present, will stop execution if the return code of the program run doesn't match
the value provided here. To verify correct execution of most programs, specify 0.

### dirs:

This is not required at all. This is just a place to put commonly used directories, and
must be referred to with `{0.dirs.<dir>}`

### init_cmds:

A list of commands to be run locally before running anything remotely. Can be useful if, e.g.,
a file must be generated which depends on some program execution's parameters.

### files:

A list of files to be copied to remote hosts at the start of shremote's execution

### commands:

**The meat of the config!**

A dictionary mapping the program instances to their arguments and the times at which they start.

Each command name should match a `program` (and optionally a `log`) as defined above.

Each command has the following fields, all optional:
* `begin`: The time (in seconds) at which to start the command. Can include references and math.
 (e.g. `{0.experiment_duration} + 5`). Can be negative, to enforce commands running earlier.
 (defaults to 0).
* `duration`: The duration for which the command should be executed (in seconds). The `stop`
part of the program's definition will be run at this time, if present.
* `enforce_duration`: If present and `True`, will halt execution of the shremote session
if the program runs for less long than specified.
* `var`: Where `var` is used in the program's `start` or `stop` definitions.
