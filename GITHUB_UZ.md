# GitHub va Render uchun qisqa yo‘riqnoma

GitHub repositoriyasining ildiziga faqat shu `web_control` papkasining **ichidagi** fayllarni yuklang. Repozitoriyada `manage.py`, `render.yaml`, `.python-version`, `requirements.txt`, `control/`, `control_config/`, `templates/` va `static/` bevosita ildizda ko‘rinishi kerak.

Desktop POS kodi, loyiha ildizidagi `BarakaTop.pyw`, `dist/`, `build/`, lokal baza va `.env` faylini bu repozitoriyga yuklamang.

Render’da **New → Blueprint** orqali GitHub repositoriyasini tanlang. Muhit qiymatlarini `.env.example` asosida Render paneliga kiriting; haqiqiy sirlarni `.env` yoki GitHub ichiga yozmang.

Supabase uchun `Connect` bo‘limidagi Shared Pooler Session mode, port `5432` manzilidan foydalaning. Birinchi deploydan so‘ng `/panel/login/` sahifasiga kiring, Telegram botni sozlang va test do‘kon/qurilma bilan aktivatsiya hamda jonli ulanishni tekshiring.
