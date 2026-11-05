# Consulta de Certidões – Abençoado

Portal somente leitura. Dados e PDFs criptografados (AES-256-GCM, chave derivada da senha via PBKDF2-SHA256).
Gerado automaticamente a partir do app "Controle de Certidões". Não edite `index.html` nem `f/` manualmente.

Geração: `python3 tools/build_portal.py --data certidoes.json --files arquivos.json --out . --password-file senha.txt --alert 10`
