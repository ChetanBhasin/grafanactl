## grafanactl resources alerting rules pull

Pull alert rules

### Synopsis

Pull alert rules from Grafana and write them to local files.

```
grafanactl resources alerting rules pull [UID]... [flags]
```

### Options

```
  -h, --help            help for pull
  -o, --output string   Output format. One of: json, yaml (default "yaml")
  -p, --path string     Path on disk in which the resources will be written (default "./resources/alerting/rules")
      --stop-on-error   Stop pulling resources when an error occurs
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

