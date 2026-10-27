# Evil-portal templates

These are the pages the captive portal serves. They are **neutral placeholders**
on purpose.

- `index.html` — the portal page. Its `<form method="post" action="/login">`
  submits to the portal; **every field is captured** and shown by
  `kestrel evil-portal creds`.
- `done.html` — shown after a submission.

## Customizing (authorized engagements only)

Copy this directory to `/etc/kestrel/evil-portal/templates/` and edit it there —
that path overrides these shipped defaults and survives updates:

```bash
sudo mkdir -p /etc/kestrel/evil-portal/templates
sudo cp /usr/local/share/kestrel/evil-portal/templates/* /etc/kestrel/evil-portal/templates/
```

Keep the form's `action="/login"` and the field `name`s you want captured.

## Rule: do not impersonate

Build pages that are honestly **your own** (a generic guest-Wi-Fi or lab login).
**Do not** make a page that imitates a real company, service, or its sign-in —
no copied logos, brand names, or look-alike login screens. The device is for
assessing networks you own or are authorized to test, not for deceiving people
into thinking they are signing in to a real service.
