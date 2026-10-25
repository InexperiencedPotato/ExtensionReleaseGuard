# Accessibility statement

ExtensionRelease Guard is a Windows desktop app built with CustomTkinter
(Tk). This statement describes what is known, not a compliance claim.

## What is known

- The app has a dark theme with high-contrast text on most surfaces; contrast
  has not been formally measured against WCAG.
- Common actions (Browse, Run, Export, Compare, filter tabs) are standard
  buttons; keyboard navigation has not been fully tested.
- CustomTkinter draws its controls itself, so **screen readers (NVDA, JAWS,
  Narrator) may not announce them correctly**. This has not been tested.
- Findings are plain text and can be exported as HTML, JSON, or TXT, which work
  with assistive technology far better than the window itself.

## Known limitations

- No tested screen-reader support.
- No light theme or adjustable text size.
- Severity is shown by label as well as colour, but this has not been audited
  for colour-blindness.

## Reporting barriers

If something in the app is hard to use, open an issue using the "Bug report"
template and describe the barrier and your setup (assistive tool and version).
Accessibility reports are treated as bugs.
