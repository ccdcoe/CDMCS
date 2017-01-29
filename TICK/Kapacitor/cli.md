# Kapacitor CLI

```
root@TICKAlerta:~# kapacitor help
Usage: kapacitor help [command]


Usage: kapacitor [options] [command] [args]

Commands:

	record          Record the result of a query or a snapshot of the current stream data.
	define          Create/update a task.
	define-template Create/update a template.
	replay          Replay a recording to a task.
	replay-live     Replay data against a task without recording it.
	enable          Enable and start running a task with live data.
	disable         Stop running a task.
	reload          Reload a running task with an updated task definition.
	push            Publish a task definition to another Kapacitor instance. Not implemented yet.
	delete          Delete tasks, templates, recordings or replays.
	list            List information about tasks, templates, recordings or replays.
	show            Display detailed information about a task.
	show-template   Display detailed information about a template.
	level           Sets the logging level on the kapacitord server.
	stats           Display various stats about Kapacitor.
	version         Displays the Kapacitor version info.
	vars            Print debug vars in JSON format.
	service-tests   Test a service.
	help            Prints help for a command.

Options:

  -skipVerify
    	Disable SSL verification (note, this is insecure). Defaults to the KAPACITOR_UNSAFE_SSL environment variable or false if not set.
  -url string
    	The URL http(s)://host:port of the kapacitord server. Defaults to the KAPACITOR_URL environment variable or http://localhost:9092 if not set.

```
