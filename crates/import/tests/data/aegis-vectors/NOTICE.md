# Test vector di terze parti

I file in questa cartella provengono dal progetto **Aegis Authenticator**
(<https://github.com/beemdevelopment/Aegis>), commit `d6f4e5925a97e4e91593f1542085eae03432a759`,
percorso `app/src/test/resources/com/beemdevelopment/aegis/importers/`.

Licenza: GPL-3.0 (compatibile con la licenza di questo progetto).

- `plain.txt`: gli account di riferimento come URI `otpauth://`.
- Gli altri file sono esportazioni reali degli stessi account create dalle rispettive app.
- La password dei file cifrati è `test`.

I file sono usati esclusivamente nei test di compatibilità degli importer.
