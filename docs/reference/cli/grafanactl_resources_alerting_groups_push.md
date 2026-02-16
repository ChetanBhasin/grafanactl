## grafanactl resources alerting groups push

Push alert rule groups

### Synopsis

Push alert rule group manifests from local files to Grafana.

```
grafanactl resources alerting groups push [flags]
```

### Options

```
      --disable-provenance   Set X-Disable-Provenance=true on write requests
  -h, --help                 help for push
  -p, --path strings         Paths on disk from which to read alert rule group manifests (default [./resources/alerting/groups])
      --stop-on-error        Stop pushing groups when an error occurs
```

### Options inherited from parent commands

```
      --config string    Path to the configuration file to use
      --context string   Name of the context to use
      --no-color         Disable color output
  -v, --verbose count    Verbose mode. Multiple -v options increase the verbosity (maximum: 3).
```

### SEE ALSO

* [grafanactl resources alerting groups](grafanactl_resources_alerting_groups.md)	 - Manage alert rule groups

