## grafanactl resources alerting rules delete

Delete alert rules

### Synopsis

Delete one or more alert rules by UID.

```
grafanactl resources alerting rules delete UID... [flags]
```

### Options

```
      --disable-provenance   Set X-Disable-Provenance=true on delete requests
  -h, --help                 help for delete
      --stop-on-error        Stop deleting rules when an error occurs
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

