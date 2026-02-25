/**
 * Simple Password Guard via Netlify Edge Functions
 * Adapted for AL VPN portal.
 */

export default async (request, context) => {
    const url = new URL(request.url);
    const cookieName = "vpn_portal_auth";
    // Получаем пароль из переменных окружения Netlify
    const SECRET_PASSWORD = Netlify.env.get("VPN_PASSWORD");

    // Если переменная не задана, выводим ошибку
    if (!SECRET_PASSWORD) {
        return new Response("Security Error: VPN_PASSWORD not set in Netlify Environment Variables.", { status: 500 });
    }

    // Разрешаем доступ к статическим ресурсам, если они понадобятся
    const whitelistedExtensions = [".css", ".js", ".png", ".svg", ".ico", ".jpg"];
    if (whitelistedExtensions.some(ext => url.pathname.endsWith(ext)) || url.pathname.startsWith("/.netlify")) {
        return context.next();
    }

    // Обработка выхода (logout)
    if (url.pathname === "/logout") {
        context.cookies.delete(cookieName);
        return new Response("Logged out", {
            status: 302,
            headers: { Location: "/" },
        });
    }

    // Обработка попытки входа
    if (request.method === "POST" && url.pathname === "/login") {
        const formData = await request.formData();
        const password = formData.get("password");

        if (password === SECRET_PASSWORD) {
            context.cookies.set({
                name: cookieName,
                value: "true",
                path: "/",
                httpOnly: true,
                secure: true,
                sameSite: "Strict",
                maxAge: 60 * 60 * 24 * 7, // 1 неделя
            });
            return new Response(null, {
                status: 302,
                headers: { Location: "/" },
            });
        } else {
            return new Response("Invalid password", { status: 401 });
        }
    }

    // Проверка сессии (куки)
    const isAuthorized = context.cookies.get(cookieName) === "true";

    if (isAuthorized) {
        return context.next();
    }

    // Если не авторизован — показываем форму входа в стиле VPN Portal
    return new Response(
        `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Access Required | VPN Portal</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #0f172a;
                --card-bg: #1e293b;
                --accent: #009FE3;
                --text: #e2e8f0;
                --muted: #94a3b8;
            }
            body { 
                font-family: 'Inter', sans-serif; 
                background: linear-gradient(135deg,#0f172a,#111827);
                color: var(--text); 
                display: flex; 
                align-items: center; 
                justify-content: center; 
                height: 100vh; 
                margin: 0; 
            }
            .login-card { 
                background: var(--card-bg); 
                padding: 2.5rem; 
                border-radius: 1.5rem; 
                box-shadow: 0 0 40px rgba(0,0,0,0.5);
                width: 100%;
                max-width: 380px;
                text-align: center;
                border: 1px solid rgba(255,255,255,0.05);
            }
            h1 { font-size: 1.5rem; margin-bottom: 0.5rem; color: #fff; }
            p { color: var(--muted); margin-bottom: 2rem; font-size: 0.9rem; }
            input { 
                width: 100%; 
                padding: 0.85rem 1rem; 
                margin-bottom: 1.2rem; 
                border-radius: 0.75rem; 
                border: 1px solid rgba(255,255,255,0.1);
                background: #0f172a;
                color: white;
                box-sizing: border-box;
                font-size: 1rem;
                outline: none;
                transition: border-color 0.3s;
            }
            input:focus {
                border-color: var(--accent);
            }
            button { 
                width: 100%; 
                padding: 0.85rem; 
                background: var(--accent); 
                color: white; 
                border: none; 
                border-radius: 0.75rem; 
                font-weight: 600; 
                cursor: pointer;
                font-size: 1rem;
                transition: opacity 0.3s;
            }
            button:hover { opacity: 0.9; }
            .locked-icon {
                font-size: 3rem;
                margin-bottom: 1rem;
                display: block;
            }
        </style>
    </head>
    <body>
        <div class="login-card">
            <span class="locked-icon">🔐</span>
            <h1>Private Access</h1>
            <p>Please enter the password to access VPN Portal</p>
            <form action="/login" method="POST">
                <input type="password" name="password" placeholder="Password" autofocus required>
                <button type="submit">Unlock</button>
            </form>
        </div>
    </body>
    </html>
    `,
        {
            status: 401,
            headers: { "content-type": "text/html" },
        }
    );
};

export const config = {
    path: "/*"
};
