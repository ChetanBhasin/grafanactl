## grafanactl resources alerting rules push

Push alert rules

### Synopsis

Push alert rule manifests from local files to Grafana.

```
grafanactl resources alerting rules push [flags]
```

### Options

```
      --disable-provenance   Set X-Disable-Provenance=true on write requests
  -h, --help                 help for push
  -p, --path strings         Paths on disk from which to read alert rule manifests (default [./resources/alerting/rules])
      --stop-on-error        Stop pushing rules when an error occurs
```

### Options inherited from parent commands

```
      --config string    Path to the configuration file to use
      --context string   Name of the context to use
      --no-color         Disable color output
  -v, --verbose count    Verbose mode. Multiple -v options increase the verbosity (maximum: 3).
```

### SEE ALSO

* [grafanactl resources alerting rules](grafanactl_resources_alerting_rules.md)	 - Manage alert rules

