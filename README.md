\# wazuh-ruletest



Regression tests for Wazuh rules and decoders. Write down which logs should

raise which alerts, run one command, and find out immediately if a rule change

broke something.



```

examples\\sshd.yml

&#x20; PASS   invalid ssh user raises 5710

&#x20; PASS   harmless log does not alert



2 passed, 0 failed, 0 errors in 0.4s

```



\## Why



Wazuh rules are hand-written XML. Edit one and you can silently break another,

and you usually find out when a real attack produces no alert. Wazuh already

ships `wazuh-logtest` for checking a single log by hand. `wazuh-ruletest` turns

those manual checks into saved, repeatable tests that run locally or in CI.



\## Install



```

pip install git+https://github.com/YOUR-GITHUB-USER/wazuh-ruletest.git

```



Requires Python 3.9+ and a Wazuh manager whose API you can reach. Developed and

tested against Wazuh 4.14.



\## Quick start



1\. Write a test file, `tests/sshd.yml`:



```yaml

tests:

&#x20; - name: invalid ssh user raises 5710

&#x20;   event: "Oct 15 21:07:00 linux-agent sshd\[29205]: Invalid user blimey from 18.18.18.18 port 48928"

&#x20;   expect:

&#x20;     rule\_id: 5710

&#x20;     level: 5

&#x20;     decoder: sshd

&#x20;     fields:

&#x20;       srcip: 18.18.18.18



&#x20; - name: harmless log does not alert

&#x20;   event: "Oct 15 21:07:00 linux-agent harmless\[1]: hello world"

&#x20;   expect:

&#x20;     alert: false

```



2\. Point the tool at your manager. The password is read only from the

&#x20;  environment, so it never appears in your shell history or process list.



```

export WAZUH\_URL=https://your-manager:55000

export WAZUH\_USER=your-api-user

export WAZUH\_PASSWORD='your-api-password'

wazuh-ruletest run tests/

```



On Windows PowerShell use `$env:WAZUH\_URL='...'` with single quotes. If your

organization blocks the generated `wazuh-ruletest.exe`, run

`python -m wazuh\_ruletest run tests/` instead.



Run it against a \*\*test or staging manager\*\*, not production.



\## Test file reference



| Key | Where | Meaning |

|---|---|---|

| `suite` | top level | Optional label for the file |

| `defaults` | top level | `log\_format` and `location` applied to every test |

| `tests` | top level | List of test cases (required) |

| `name` | test | Name shown in results |

| `event` | test | The raw log line (required) |

| `log\_format`, `location` | test | Override the defaults (`syslog` and `master->/var/log/syslog`) |

| `expect` | test | What should happen (required) |

| `alert` | expect | `true` (default) or `false` for "must not alert" |

| `rule\_id` | expect | Rule that must match |

| `level` | expect | Rule level that must match |

| `decoder` | expect | Decoder that must match |

| `fields` | expect | Decoded fields that must match. Nested fields use dotted paths such as `win.eventdata.image` |



Only the properties you list are checked. A misspelled key is an error, so a

typo can never produce a test that silently checks nothing.



\## Command line



```

wazuh-ruletest run PATH \[PATH ...] \[--url URL] \[--user USER]

&#x20;                 \[--insecure | --ca-cert FILE] \[--timeout SECONDS]

&#x20;                 \[--junit FILE]

```



| Exit code | Meaning |

|---|---|

| 0 | All tests passed |

| 1 | At least one test failed (a rule behaved differently than expected) |

| 2 | The run could not complete (bad arguments, invalid test file, login or connection problem) |



TLS certificates are verified by default. For a lab with a self-signed

certificate, pass `--ca-cert FILE`, or `--insecure` for throwaway setups.



\## Use in CI



A reusable GitHub Action is included. See

\[`examples/github-workflow.yml`](examples/github-workflow.yml) for a complete

workflow. GitHub's hosted runners cannot reach a private Wazuh manager, so use a

self-hosted runner on the same network as a staging manager. `--junit FILE`

writes a JUnit XML report that most CI systems can display.



\## Limitations



\- Every test runs in a fresh logtest session, so rules that need several events

&#x20; (frequency or brute-force rules) cannot be tested yet.

\- It needs a running Wazuh manager. Starting a temporary one in Docker is planned.

\- Rules, decoders and fields are checked. Active responses and integrations are not.



\## Roadmap



\- Multi-event tests for frequency-based rules

\- Throwaway Docker manager, so CI needs no infrastructure

\- ATT\&CK coverage report

\- Community test packs for common log sources



\## Contributing



Issues and pull requests are welcome. The easiest way to help is a test pack:

sample logs for a common source (sshd, nginx, Windows events) with the

detections they should trigger. Run the unit tests, which need no Wazuh server,

with `pip install -e ".\[dev]"` and `python -m pytest`.



\## Disclaimer



Independent open-source project, not affiliated with or endorsed by Wazuh, Inc.

Wazuh is a trademark of its owner.



\## License



MIT

