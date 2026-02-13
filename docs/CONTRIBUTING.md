# Contributing / Руководство для контрибьюторов

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/<your-username>/sentinel-ddos.git
   cd sentinel-ddos
   ```
3. Create a branch:
   ```bash
   git checkout -b feature/my-feature
   ```

## Development Setup

### Backend
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Dashboard
```bash
cd dashboard
npm install
npm run dev
```

### Running Tests
```bash
pytest
```

## Code Style

- **Python**: Follow PEP 8. Use type hints. We use `ruff` for linting.
- **TypeScript**: ESLint + Prettier. Strict TypeScript.

## Pull Request Process

1. Ensure tests pass
2. Update documentation if needed
3. Write a clear PR description
4. Reference any related issues

## Reporting Issues

Use GitHub Issues. Include:
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, Docker version)

---

Мы рады любому вкладу! Если у вас есть вопросы — создайте Issue или напишите в Discussions.
