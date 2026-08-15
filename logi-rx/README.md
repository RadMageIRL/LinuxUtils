# logi-rx

Audit and tune a Logitech wireless receiver on Linux.

Wireless receiver problems on Linux tend to get misdiagnosed as range problems
when they are actually power-management or configuration problems. `logi-rx`
checks the settings that matter, fixes the ones it safely can, and gives you a
measurement tool for the ones it cannot, so you can tell an RF problem from a
software problem instead of guessing.

Standard library only. No dependencies.

## Quick start

```sh
./logi-rx.py                 # audit everything, change nothing
./logi-rx.py --json          # same data, machine-readable
sudo ./logi-rx.py --apply    # apply runtime fixes + install persistent udev rule
./logi-rx.py --watch         # measure link quality empirically
sudo ./logi-rx.py --revert   # remove the udev rule
```

The default invocation is read-only. Nothing on your system changes unless you
pass `--apply`, and `--revert` undoes everything `--apply` does.

## Statuses

The same six-status model the other tools in this repo use:

| Status | Meaning | Affects exit code |
|--------|---------|-------------------|
| `ok` | Checked and fine | no |
| `warn` | Worth fixing | **yes** |
| `fail` | Actively broken | **yes** |
| `unknown` | Could not determine | no |
| `skipped` | Does not apply to this device | no |
| `info` | Reported without judgement | no |

`skipped` is distinct from `ok` on purpose, and the distinction is load-bearing
here. `power/wakeup` **not being exposed** means the device never advertised
remote-wakeup capability, so there is no setting to change: that is `skipped`.
`power/wakeup` being **disabled** is actionable: that is `warn`. Reporting the
first as a warning sends you hunting for a setting that does not exist.

Anything unreadable for want of root is `unknown`, never a failure.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Nothing to fix |
| `1` | Findings to act on |
| `2` | Could not determine |

**`1` means, and only means, that there is a finding to act on.** `2` covers
every case where no verdict was reached: not Linux, no Logitech device present,
the named `--device` not found, `--apply` or `--revert` without root, no read
access to the event node, and a watch run with nothing to measure.

`unknown` deliberately does not affect the exit code, for the same reason it
does not in `freshcheck`: a run that could not answer a question should not look
like a failure. `rfscan` and `freshcheck` in this repo draw the identical line,
so a cron job can treat all three alike.

## What it checks

### USB topology

Reports which bus and root hub the receiver enumerated on, the host controller's
PCI address, and a table of every USB root hub with its speed and port count.
Informational: it is context, not a finding.

It explicitly **does not** claim to detect whether the physical port is USB 2 or
USB 3. It cannot, and neither can anything else reading sysfs: a full-speed HID
device always enumerates on the USB 2 companion bus, whether you plugged it into
a black port or a blue one. The two are indistinguishable from software. Use
`--watch` to test ports empirically instead.

### Devices sharing the host controller

The tool already resolves the parent PCI controller for the ACPI check, so it
also enumerates what else is enumerated behind it.

This matters because USB 3 SuperSpeed signalling emits broadband noise into the
2.4 GHz band. A receiver sharing a controller with an external SSD, or on an
extension cable routed alongside one, sits in a raised noise floor and loses a
meaningful chunk of its effective range.

Reported as `info`, never as a finding. **It is a correlation, not a
diagnosis**: it says a plausible noise source is nearby, not that it is causing
your problem. `--watch` with the neighbour unplugged is what would settle it.

Root hubs are not counted as neighbours. Every modern xHCI controller exposes a
SuperSpeed root hub, so counting those would make this fire on essentially every
machine, which is how a finding becomes noise people learn to skip past. Only
devices below the hubs count, and only genuinely SuperSpeed ones are flagged as
such: a USB 2 webcam is listed but is not a broadband noise source.

### Kernel module

Verifies `hid_logitech_dj` is loaded or built in. Without it the receiver
presents as a single generic HID device, and per-device battery reporting and
pairing do not work.

### USB autosuspend

Checks `power/control`. When the kernel is allowed to autosuspend an input
receiver, the first input after an idle period gets swallowed while the device
resumes. This reads as a dropped click or an ignored flick of the pointer and is
easy to mistake for a range problem. `--apply` sets it to `on`.

Not exposed at all means runtime power management does not apply to this device:
`skipped`, not a warning.

### USB remote wakeup

Checks `power/wakeup`. When disabled, the keyboard cannot resume the machine
from suspend, the classic complaint about Logitech media keyboards, and a
settings problem rather than a hardware limitation. `--apply` sets it to
`enabled`. See the note on `skipped` above for the not-exposed case.

### ACPI controller wakeup

Resolves the receiver's parent xHCI controller and reports its
`/proc/acpi/wakeup` state. **This gates everything above**: if the controller is
masked in ACPI, the per-port `power/wakeup` setting you just enabled does
nothing.

`logi-rx` deliberately will not change this for you. Writing a device name to
`/proc/acpi/wakeup` is a *toggle*, not a set, so a script that runs it twice
silently undoes its own work. There is no way to make it idempotent. The tool
reports the state and hands you the command to run exactly once.

### Battery

Reads battery level directly from the `hidpp_battery` power-supply class. No
`solaar` required, though `solaar` is checked for and recommended since it is
useful for pairing and button remapping.

Not every device reports battery over HID++, including some K400 revisions. When
no reading is available the tool reports `skipped` rather than inventing one.

Worth knowing regardless: falling alkaline voltage reduces transmit power well
before any low-battery indicator fires. If range degrades gradually over months,
swap cells before debugging RF. Lithium AA cells (Energizer L91) hold ~1.5 V
nearly flat to end of life and are worth it in a device you do not want to think
about.

### Persistent udev rule

Runtime sysfs writes are lost on reboot and on re-plug. `--apply` installs
`/etc/udev/rules.d/90-logitech-receiver.rules`.

The rule is generated against the **specific** vendor and product ID of the
detected receiver rather than matching all Logitech devices, so it will not
affect an unrelated webcam or headset.

`--revert` removes it, but **only if it carries this tool's managed marker**. A
file at that path which `logi-rx` did not write is not `logi-rx`'s to delete, so
a hand-written rule is left alone with a note rather than destroyed.

`--apply` is idempotent. A second run over an already-fixed system reports `ok`
and writes nothing, which is asserted by a test.

## Watch mode

```sh
./logi-rx.py --watch
./logi-rx.py --watch --duration 60
./logi-rx.py --watch --json > before.json
```

Locates the pointer's evdev node via `/proc/bus/input/devices`, reads raw
`input_event` structs, and measures the intervals between motion events. Only an
interface with a `mouse` handler qualifies: the receiver also presents a
keyboard-only interface, and selecting that one would produce a run with no
motion at all.

### The threshold calibrates itself

A fixed millisecond threshold means different things on different hardware. A
Unifying receiver reports at 125 Hz, so 8 ms is nominal; a Lightspeed mouse runs
at 1000 Hz, where 1 ms is. A flat 100 ms figure is twelve missed reports on one
and a hundred on the other, flagged identically.

So the threshold is derived from the device's own measured median interval, at
**10x** that median, and the derived figure is reported in the output so you can
see what it calibrated to. The multiplier leaves room for ordinary scheduling
jitter; a threshold set close to the median would report a healthy link as
dropping hundreds of reports.

`--gap-ms` remains as an explicit override and disables calibration when given.

Below 50 motion samples the median is not stable enough to calibrate against, so
the run reports `unknown` rather than deriving a confident threshold from noise.

### It tells a dropout from you letting go of the mouse

The old version could not, which is why it used to insist you move the pointer
continuously or the results were meaningless. It now reads the movement delta on
each event, not just the event's existence, and classifies each gap by the
motion velocity in the samples **immediately adjacent** to it:

- A **user pause** tapers. Deltas shrink toward zero, then the gap, then they
  ramp back up.
- A **dropout** does not. Full-velocity motion, gap, full-velocity motion.

Two details make this work, and both were arrived at by watching a simpler
version fail:

- Only the few samples either side of the gap are averaged, not a whole window.
  A window mean is dominated by the fast samples at the start of a taper, which
  makes a real pause read as a dropout.
- The "was it actually moving" floor is **relative to the session's own median
  delta**, not an absolute number. An absolute floor is calibrated to one DPI
  setting and one user's hand speed, and it misreads slow-but-deliberate motion
  as a pause.

Gaps are classified and counted separately: dropouts are a `fail`, pauses are
`info`. Continuous motion still gives the cleanest read, so the instruction
stays in the output, but it is now advice rather than a correctness requirement.

### A/B testing ports

The point is comparison. Run it from where you actually sit, move the receiver
to a different port or position, and run it again from the same spot.

`--watch --json` makes that mechanical rather than a matter of eyeballing two
terminals:

```sh
./logi-rx.py --watch --json > before.json
# move the dongle
./logi-rx.py --watch --json > after.json
diff <(jq .watch.dropouts before.json) <(jq .watch.dropouts after.json)
```

- **Gap count drops a lot**: the old port or placement was the problem.
- **No change**: the band itself is the suspect. `rfscan` in this repo maps
  2.4 GHz occupancy and will tell you whether your WiFi is sitting on top of the
  receiver. The two tools answer halves of one question, and `rfscan` names
  `logi-rx --watch` as its ground truth in turn.
- **Clean run at your desk, bad run at the couch**: it is range, and no amount
  of configuration will fix it. The transmitter is the limit.

Needs read access to `/dev/input/event*`: either run with `sudo`, or add
yourself to the `input` group and log back in.

```sh
sudo usermod -aG input "$USER"
```

## Options

| Flag | Description |
|------|-------------|
| `--apply` | Apply fixes and install the udev rule. Requires root. |
| `--revert` | Remove the udev rule, if this tool wrote it. Requires root. |
| `--watch` | Measure input-event gaps. |
| `--duration N` | Watch duration in seconds. Default 30. |
| `--gap-ms N` | Explicit dropout threshold in ms. Omit to calibrate. |
| `--device NAME` | Force a sysfs device node, e.g. `1-3`. |
| `--json` | Machine-readable output. |
| `--no-color` | Disable coloured output. |

When multiple Logitech devices are present the tool picks the most
receiver-looking one and tells you what else it found. Use `--device` to
override.

## JSON output

| Key | Type | Meaning |
|-----|------|---------|
| `tool` | string | Always `"logi-rx"` |
| `linux` | bool | Whether the platform check passed |
| `mode` | string | `audit`, `watch`, or `revert` |
| `root` | bool | Whether the run was privileged |
| `receiver` | object\|null | The chosen device: `name`, `pid`, `product`, `label`, `path`, `busnum`, `devnum`, `speed` |
| `other_logitech_devices` | array | Other 046d devices, with `name`, `product`, `pid` |
| `results` | array | Findings, see below |
| `watch` | object\|null | Watch analysis, see below |
| `applied` | array | Changes made under `--apply`, empty otherwise |
| `counts` | object | Count per status |
| `error` | string\|null | `not-linux`, `no-device`, `device-not-found`, `needs-root`, `watch-inconclusive` |
| `exit_code` | int | Matches the process exit code |

Each entry in `results`: `id`, `check`, `title`, `status`, `summary`, `detail`
(array), `fix` (string or null). A single check can emit more than one finding,
which is why `id` and `check` are separate.

The `watch` object:

| Key | Type | Meaning |
|-----|------|---------|
| `motion_events` | int | Samples recorded |
| `duration_s` | number\|null | Span covered by the samples |
| `median_gap_ms` | number\|null | The device's measured report interval |
| `median_delta` | number\|null | Session median movement delta, in counts |
| `threshold_ms` | number\|null | The threshold actually used |
| `threshold_source` | string\|null | `calibrated` or `explicit`; null if it could not be derived |
| `median_ms` / `p99_ms` / `worst_ms` | number\|null | Interval distribution |
| `gaps` | array | Each with `at_s`, `gap_ms`, `classification` (`dropout`/`pause`), `velocity_before`, `velocity_after` |
| `dropouts` / `pauses` | int | Counts by classification |
| `axis_counts` | object | Samples per axis, `x` and `y` |

## Tests

```sh
python3 -m unittest discover -s logi-rx/tests -t logi-rx/tests -v
```

This is the only tool in the repo that writes to the system, which inverts the
usual risk ordering, so the write paths get the most attention: `--apply` is
checked for idempotency, the generated udev rule for pinning the specific
product ID rather than every Logitech device, and `--revert` for refusing to
delete a file it did not write.

Three harnesses match the shape of the real system:

- **A synthetic sysfs tree** with the real `/sys/devices/pci.../usbN/1-3` layout
  behind `/sys/bus/usb/devices` symlinks, so `root_hub_for()` and
  `pci_controller_for()` are exercised rather than stubbed, plus a second
  Logitech device to test disambiguation and `--device`.
- **`/proc/bus/input/devices` fixtures** covering the keyboard-only interface
  (must be skipped), the pointer interface (must be selected), a non-Logitech
  mouse (must be ignored), and the no-match case.
- **An evdev byte stream**, fed from a file everywhere and from a real FIFO
  where the platform has them, verifying struct parsing and that a key event is
  never counted as motion.

Every tuning constant is pinned by a mutation test: perturb it in both
directions and confirm the tests that claim to pin it actually fail. The suite
also passes the name-versus-assertion audit used on the other two tools.

The sysfs-layout tests need directory symlinks and colons in path names. Both
hold on Linux, which is where this tool runs; a host without them skips those
rather than testing a fiction.

## Notes

Detection does not depend on the built-in list of receiver product IDs being
complete: the list only ranks candidates when several Logitech devices are
attached. Any Logitech USB device can be targeted with `--device`.

The tool reads sysfs directly and does not shell out for its checks. The only
external commands it ever runs are `udevadm control --reload` and
`udevadm trigger`, both under `--apply` or `--revert`.
