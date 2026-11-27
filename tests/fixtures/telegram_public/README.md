# telegram_public fixtures (batch p1-G05-1, P112)

Real t.me pages captured from the research datacenter egress (no cookies, no account), minimised; media
tokens shortened to `EXAMPLEMEDIA` (the CDN host is kept so the tests prove media URLs are never emitted
or requested).

| file | provenance |
|---|---|
| `channel.html` | REAL 2026-11-25, t.me/telegram (official channel) |
| `user.html` | REAL 2026-11-26, t.me/BotSupport (user account operated by Telegram) |
| `bot.html` | REAL 2026-11-26, t.me/BotFather |
| `group.html` | REAL 2026-11-26, t.me/pythontelegrambotgroup (public group of an open-source project) |
| `generic_contact.html` | REAL 2026-11-26, generic 'Contact @x' page of a random control handle (marker `telegram_public_generic_page`) |
| `private_channel.http.json` | REAL 2026-11-26: t.me/s/<control> -> 302 -> generic page (private or missing channel) |
| `channel_posts.html` | REAL 2026-11-26, t.me/s/telegram cut to 5 of 20 posts |
| `channel_posts_truncated.html` | the same page cut inside post 452 (malformed/partial HTML) |
| `channel_posts_ioc.html` | SYNTHETIC: real t.me/s markup with documentation values (IOCs, test card 4111..., invalid CPF-like numbers, 5555-01xx phones, example.com addresses, fake credential lines). Bot-token and webhook placeholders `{{TG_BOT_TOKEN}}`, `{{DISCORD_WEBHOOK_PATH}}` are filled by the tests at run time so no secret-shaped string is committed |
| `examplecti_profile.html`, `examplecti_older.html` | SYNTHETIC: real markup with documentation values (profile and older page of the example channel) |
