# WannaCry Core Loader — Pacote de Engenharia Reversa Estática

Pacote de análise do loader central da amostra:

```text
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
```

Preparado para publicação por **Victor Duarte Melo (Fr0ggy_)**.

Este repositório não inclui o malware original nem os executáveis extraídos. Ele contém relatório, evidências textuais, mapeamento de funções, C reconstruído para leitura, regra YARA e scripts de extração estática.

## Principais achados

- Loader PE32 x86 compilado com toolchain da era Visual C++ 6.
- Sem packer convencional; a alta entropia vem do arquivo criptografado em `.rsrc`.
- Recurso customizado `XIA`, ID `2058`, idioma `1033`, offset `0x100F0`.
- ZIP interno protegido por `WNcry@2ol7`.
- Nome de serviço e pasta derivado deterministicamente do hostname.
- Persistência por serviço automático, com fallback via `CreateProcessA` oculto.
- Diretório salvo em `Software\WanaCrypt0r`, valor `wd`, tentando HKLM e HKCU.
- Alteração de `c.wnry` para escolher uma das três carteiras Bitcoin.
- `t.wnry` validado por `WANACRY!`, chave simétrica protegida por RSA, descriptografia Rijndael/AES e carregamento manual do PE.
- Resolução e chamada da exportação `TaskStart(NULL, NULL)`.

O relatório completo está em [`docs/ANALYSIS.md`](docs/ANALYSIS.md). A análise é completa para o loader externo examinado nesta fase; os componentes internos continuam listados em [`docs/OPEN_QUESTIONS.md`](docs/OPEN_QUESTIONS.md).
