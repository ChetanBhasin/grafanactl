## grafanactl resources alerting rules validate

Validate alert rule manifests

### Synopsis

Validate alert rule manifests from local files.

```
grafanactl resources alerting rules validate [flags]
```

### Options

```
  -h, --help            help for validate
  -o, --output string   Output format. One of: json, text, yaml (default "text")
  -p, --path strings    Paths on disk from which to read alert rule manifests (default [./resources/alerting/rules])
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

* [grafanactl resources alerting rules](grafanactl_resources_alerting_rules.md)	 - Manage alert rules

