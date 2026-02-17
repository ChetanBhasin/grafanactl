## grafanactl resources alerting groups validate

Validate alert rule group manifests

### Synopsis

Validate alert rule group manifests from local files.

```
grafanactl resources alerting groups validate [flags]
```

### Options

```
  -h, --help            help for validate
  -o, --output string   Output format. One of: json, text, yaml (default "text")
  -p, --path strings    Paths on disk from which to read alert rule group manifests (default [./resources/alerting/groups])
      --stop-on-error   Stop validating resources when an error occurs
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

