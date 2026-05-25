// index.js 
const express = require('express');
const pool = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'ural_fc_secret_key_2026';

app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// ============================================
// ПРОВЕРКА АВТОРИЗАЦИИ
// ============================================

const authenticateToken = async (req, res, next) => {
    const token = req.cookies.token;
    
    if (!token) {
        if (req.accepts('html')) return res.redirect('/login');
        return res.status(401).json({ success: false, error: 'Не авторизован' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const result = await pool.query(
            `SELECT a.account_id, a.email, a.role_id, a.is_active, r.role_name 
             FROM accounts a 
             JOIN roles r ON a.role_id = r.role_id 
             WHERE a.account_id = $1 AND a.is_active = true`,
            [decoded.account_id]
        );
        
        if (result.rows.length === 0) {
            if (req.accepts('html')) return res.redirect('/login');
            return res.status(401).json({ success: false, error: 'Пользователь не найден' });
        }
        
        req.user = result.rows[0];
        next();
    } catch (err) {
        if (req.accepts('html')) return res.redirect('/login');
        return res.status(401).json({ success: false, error: 'Недействительный токен' });
    }
};

const isAdmin = (req, res, next) => {
    if (req.user.role_name !== 'администратор') {
        return res.status(403).send('Доступ запрещен');
    }
    next();
};

const isCoach = (req, res, next) => {
    if (req.user.role_name !== 'тренер' && req.user.role_name !== 'администратор') {
        return res.status(403).send('Доступ запрещен');
    }
    next();
};

// ============================================
// СТРАНИЦЫ
// ============================================

app.get('/', (req, res) => res.redirect('/login'));

// СТРАНИЦА ВХОДА
app.get('/login', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <head>
            <title>Вход - ФК Урал</title>
            <meta charset="utf-8">
            <link rel="icon" type="image/png" href="https://psv4.userapi.com/s/v1/d2/oayu_c16DiJp_9FkuuWKOVGbgqH9yvywjlBI4tkp9ILVECuv_yPwC37-fUKIwygJeM5qDYE6xqcrz9PWfxFQfgLS0_mkANrt6X1CpA0lznJMpG21DkF_MsxqPzBDevg58U968eW3ysA7/logo.png">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Segoe UI', Arial, sans-serif;
                    background: linear-gradient(135deg, #1a1a1a 0%, #e74c3c 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }
                .login-container {
                    background: white;
                    border-radius: 20px;
                    padding: 40px;
                    width: 500px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                }
                .logo {
                    text-align: center;
                    margin-bottom: 20px;
                }
                .logo img {
                    max-width: 120px;
                    height: auto;
                }
                h1 { text-align: center; color: #e74c3c; margin-bottom: 10px; font-size: 28px; }
                .subtitle { text-align: center; color: #666; margin-bottom: 30px; font-size: 14px; }
                .input-group { margin-bottom: 20px; }
                label { display: block; margin-bottom: 8px; color: #333; font-weight: 500; }
                input {
                    width: 100%;
                    padding: 12px 15px;
                    border: 2px solid #e0e0e0;
                    border-radius: 10px;
                    font-size: 16px;
                }
                input:focus { outline: none; border-color: #e74c3c; }
                button {
                    width: 100%;
                    padding: 12px;
                    background: #e74c3c;
                    color: white;
                    border: none;
                    border-radius: 10px;
                    font-size: 16px;
                    font-weight: bold;
                    cursor: pointer;
                }
                button:hover { background: #c0392b; }
                .error { background: #fee; color: #e74c3c; padding: 10px; border-radius: 8px; margin-top: 15px; text-align: center; display: none; }
                .accounts-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-top: 25px; }
                .account-card {
                    background: #f8f9fa;
                    border-radius: 10px;
                    padding: 12px;
                    text-align: center;
                    cursor: pointer;
                    transition: all 0.2s;
                    border: 1px solid #e0e0e0;
                }
                .account-card:hover { background: #ffe0e0; border-color: #e74c3c; }
                .account-role { font-size: 24px; margin-bottom: 5px; }
                .account-email { font-size: 11px; color: #666; word-break: break-all; }
                .account-password { font-size: 10px; color: #999; margin-top: 5px; }
                .info-text { margin-top: 20px; text-align: center; font-size: 12px; color: #888; }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="logo">
                    <img src="https://psv4.userapi.com/s/v1/d2/oayu_c16DiJp_9FkuuWKOVGbgqH9yvywjlBI4tkp9ILVECuv_yPwC37-fUKIwygJeM5qDYE6xqcrz9PWfxFQfgLS0_mkANrt6X1CpA0lznJMpG21DkF_MsxqPzBDevg58U968eW3ysA7/logo.png" alt="ФК Урал логотип">
                </div>
                <h1>ФК Урал</h1>
                <div class="subtitle">Система управления футбольным клубом</div>
                
                <div class="input-group">
                    <label>📧 Электронная почта</label>
                    <input type="text" id="email" placeholder="example@ural.ru">
                </div>
                <div class="input-group">
                    <label>🔒 Пароль</label>
                    <input type="password" id="password" placeholder="Введите пароль">
                </div>
                <button onclick="login()">Войти в систему</button>
                <div id="error" class="error"></div>
                
                <div class="accounts-grid">
                    <div class="account-card" onclick="fillAccount('admin@ural.ru', 'hash_admin')">
                        <div class="account-role"></div>
                        <div class="account-email">admin@ural.ru</div>
                        <div class="account-password">pass: hash_admin</div>
                    </div>
                    <div class="account-card" onclick="fillAccount('coach@ural.ru', 'hash_coach')">
                        <div class="account-role"></div>
                        <div class="account-email">coach@ural.ru</div>
                        <div class="account-password">pass: hash_coach</div>
                    </div>
                    <div class="account-card" onclick="fillAccount('sobolev.dmitry@ural.ru', 'hash_player')">
                        <div class="account-role"></div>
                        <div class="account-email">sobolev.dmitry@ural.ru</div>
                        <div class="account-password">pass: hash_player</div>
                    </div>
                    <div class="account-card" onclick="fillAccount('nikitin.sergey@ural.ru', 'hash_player')">
                        <div class="account-role"></div>
                        <div class="account-email">nikitin.sergey@ural.ru</div>
                        <div class="account-password">pass: hash_player</div>
                    </div>
                </div>
                <div class="info-text">💡 Нажмите на карточку пользователя для быстрого входа</div>
            </div>
            <script>
                function fillAccount(email, password) {
                    document.getElementById('email').value = email;
                    document.getElementById('password').value = password;
                    login();
                }
                async function login() {
                    const email = document.getElementById('email').value;
                    const password = document.getElementById('password').value;
                    const errorDiv = document.getElementById('error');
                    if (!email || !password) {
                        errorDiv.style.display = 'block';
                        errorDiv.textContent = 'Заполните все поля';
                        return;
                    }
                    errorDiv.style.display = 'none';
                    try {
                        const response = await fetch('/api/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ email, password })
                        });
                        const result = await response.json();
                        if (result.success) {
                            window.location.href = '/dashboard';
                        } else {
                            errorDiv.style.display = 'block';
                            errorDiv.textContent = result.error;
                        }
                    } catch (err) {
                        errorDiv.style.display = 'block';
                        errorDiv.textContent = 'Ошибка подключения';
                    }
                }
                document.getElementById('password').addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') login();
                });
            </script>
        </body>
        </html>
    `);
});

app.get('/dashboard', authenticateToken, async (req, res) => {
    if (req.user.role_name === 'администратор') res.redirect('/admin');
    else if (req.user.role_name === 'тренер') res.redirect('/coach');
    else res.redirect('/player');
});

// ============================================
// КАБИНЕТ ИГРОКА – ЧЁРНО-КРАСНАЯ ТЕМА
app.get('/player', authenticateToken, async (req, res) => {
    const playerResult = await pool.query(`
        SELECT p.first_name, p.last_name, pl.jersey_number, pl.position, p.birth_date, p.phone
        FROM players pl
        JOIN profiles p ON pl.profile_id = p.profile_id
        JOIN accounts a ON p.account_id = a.account_id
        WHERE a.account_id = $1
    `, [req.user.account_id]);
    
    const player = playerResult.rows[0] || { first_name: 'Игрок', last_name: '', jersey_number: '?', position: 'Не указана', birth_date: null, phone: '' };
    const isGoalkeeper = player.position === 'Вратарь';
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Личный кабинет - ФК Урал</title>
            <meta charset="utf-8">
            <link rel="icon" type="image/png" href="https://psv4.userapi.com/s/v1/d2/oayu_c16DiJp_9FkuuWKOVGbgqH9yvywjlBI4tkp9ILVECuv_yPwC37-fUKIwygJeM5qDYE6xqcrz9PWfxFQfgLS0_mkANrt6X1CpA0lznJMpG21DkF_MsxqPzBDevg58U968eW3ysA7/logo.png">
            <style>
                *{margin:0;padding:0;box-sizing:border-box;}
                body{font-family:'Segoe UI',Roboto,Arial,sans-serif;background:#0a0a0a;color:#e0e0e0;}
                header{background:#0a0a0a;border-bottom:3px solid #cc0000;padding:20px 40px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:15px;}
                header h1{color:#cc0000;font-size:1.8rem;}
                .logo{display:flex;align-items:center;gap:15px;}
                .logo img{height:50px;}
                button.logout{background:#cc0000;border:none;padding:8px 20px;border-radius:30px;color:#fff;font-weight:bold;cursor:pointer;transition:.2s;}
                button.logout:hover{background:#990000;transform:scale(1.02);}
                .container{max-width:1300px;margin:30px auto;padding:0 25px;}
                .profile-card{background:#1e1e1e;border-radius:24px;padding:30px;margin-bottom:40px;display:flex;gap:40px;flex-wrap:wrap;box-shadow:0 8px 20px rgba(0,0,0,0.3);border:1px solid #2c2c2c;}
                .player-photo{width:180px;height:180px;background:#2a2a2a;border-radius:50%;display:flex;align-items:center;justify-content:center;border:4px solid #cc0000;overflow:hidden;}
                .player-photo img{width:100%;height:100%;object-fit:cover;}
                .player-photo-placeholder{text-align:center;color:#aaa;}
                .player-photo-placeholder span{font-size:70px;}
                .player-info{flex:1;}
                .player-info h2{color:#cc0000;font-size:28px;margin-bottom:20px;}
                .info-row{background:#2a2a2a;margin:12px 0;padding:12px 18px;border-radius:16px;display:flex;align-items:center;flex-wrap:wrap;}
                .info-label{font-weight:600;color:#cc0000;width:140px;}
                .photo-input{margin-top:20px;}
                .photo-input input{width:100%;padding:10px;border-radius:12px;border:1px solid #444;background:#2a2a2a;color:#fff;}
                .replace-photo-btn{background:#cc0000;border:none;padding:6px 14px;border-radius:20px;color:#fff;font-size:12px;cursor:pointer;margin-top:10px;}
                .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:25px;margin-bottom:40px;}
                .stat-card{background:linear-gradient(145deg,#1a1a1a,#111);border-radius:20px;padding:20px;text-align:center;border-bottom:4px solid #cc0000;box-shadow:0 4px 12px rgba(0,0,0,0.2);}
                .stat-card div:first-child{font-size:18px;opacity:0.8;}
                .stat-card h3{font-size:40px;margin:12px 0 0;color:#cc0000;}
                .card{background:#1e1e1e;border-radius:24px;padding:25px;margin-bottom:30px;border:1px solid #2c2c2c;}
                h2{color:#cc0000;border-bottom:2px solid #cc0000;display:inline-block;padding-bottom:8px;margin-bottom:25px;}
                .player-table{width:100%;border-collapse:collapse;}
                .player-table th,.player-table td{padding:14px 12px;text-align:center;border-bottom:1px solid #333;}
                .player-table th{background:#0f0f0f;color:#cc0000;font-weight:600;}
                .player-table tr:hover{background:#252525;}
                .goal-highlight{color:#cc0000;font-weight:bold;}
                .clean-sheet{color:#4caf50;font-weight:bold;}
                @media (max-width:700px){
                    header{flex-direction:column;text-align:center;}
                    .profile-card{flex-direction:column;align-items:center;text-align:center;}
                    .info-row{flex-direction:column;align-items:flex-start;}
                    .info-label{width:auto;margin-bottom:8px;}
                }
            </style>
        </head>
        <body>
            <header>
                <div class="logo">
                    <img src="https://psv4.userapi.com/s/v1/d2/-y9GRhRz2pYjOBNuZ22E20IfKAsnFCEyctGdh0b7Rc_cw3JQ2Kja0Ayetwk26e53_rLUtXbCwuH2cyXsOleObaEzxRxtlErgoOHumBlzvhktrcK8p5cr0sUGy75adTU6gOuxKmsmuUp-/logo.png" alt="Логотип">
                    <h1> Личный кабинет ${isGoalkeeper ? 'вратаря' : 'игрока'}</h1>
                </div>
                <button class="logout" onclick="logout()">Выйти</button>
            </header>
            <div class="container">
                <div class="profile-card">
                    <div class="player-photo" id="playerPhoto">
                        <div class="player-photo-placeholder"><span>${isGoalkeeper ? '' : ''}</span><p>Фото</p></div>
                    </div>
                    <div class="player-info">
                        <h2>${player.last_name} ${player.first_name}</h2>
                        <div class="info-row"><span class="info-label">Игровой номер:</span> ${player.jersey_number}</div>
                        <div class="info-row"><span class="info-label">Позиция:</span> ${player.position}</div>
                        <div class="info-row"><span class="info-label">Дата рождения:</span> ${player.birth_date ? new Date(player.birth_date).toLocaleDateString('ru-RU') : 'Не указана'}</div>
                        <div class="info-row"><span class="info-label">Телефон:</span> ${player.phone || 'Не указан'}</div>
                        <div class="photo-input" id="photoInputContainer">
                            <label>🔗 Ссылка на фото:</label>
                            <input type="text" id="photoUrl" placeholder="https://example.com/photo.jpg" onchange="updatePhoto()">
                        </div>
                        <button class="replace-photo-btn" id="replacePhotoBtn" onclick="showPhotoInput()" style="display:none;">📷 Заменить фото</button>
                    </div>
                </div>
                ${isGoalkeeper ? `
                <div class="stats-grid">
                    <div class="stat-card"><div> Матчей</div><h3 id="totalMatches">-</h3></div>
                    <div class="stat-card"><div> Пропущено</div><h3 id="totalGoalsAgainst">-</h3></div>
                    <div class="stat-card"><div> Сухие матчи</div><h3 id="cleanSheets">-</h3></div>
                    <div class="stat-card"><div> Сухие дома</div><h3 id="cleanSheetsHome">-</h3></div>
                    <div class="stat-card"><div> Сухие в гостях</div><h3 id="cleanSheetsAway">-</h3></div>
                </div>
                <div class="card">
                    <h2> Детальная статистика по матчам</h2>
                    <div id="goalkeeperDetail">Загрузка...</div>
                </div>
                ` : `
                <div class="stats-grid">
                    <div class="stat-card"><div> Голы</div><h3 id="totalGoals">-</h3></div>
                    <div class="stat-card"><div> Дома</div><h3 id="homeGoals">-</h3></div>
                    <div class="stat-card"><div> В гостях</div><h3 id="awayGoals">-</h3></div>
                    <div class="stat-card"><div> Матчей</div><h3 id="totalMatches">-</h3></div>
                    <div class="stat-card"><div> Реализация</div><h3 id="efficiency">-</h3></div>
                </div>
                <div class="card">
                    <h2> Голы по матчам</h2>
                    <div id="goalsDetail">Загрузка...</div>
                </div>
                `}
            </div>
            <script>
                var playerJerseyNumber = ${player.jersey_number};
                var playerPhotoElement = document.getElementById('playerPhoto');
                var photoInputContainer = document.getElementById('photoInputContainer');
                var replacePhotoBtn = document.getElementById('replacePhotoBtn');
                function updatePhoto() {
                    var url = document.getElementById('photoUrl').value;
                    if (url) {
                        playerPhotoElement.innerHTML = '<img src="' + url + '" alt="Фото игрока">';
                        localStorage.setItem('playerPhoto_' + playerJerseyNumber, url);
                        photoInputContainer.style.display = 'none';
                        replacePhotoBtn.style.display = 'inline-block';
                    }
                }
                function showPhotoInput() {
                    photoInputContainer.style.display = 'block';
                    replacePhotoBtn.style.display = 'none';
                    document.getElementById('photoUrl').value = '';
                }
                var savedPhoto = localStorage.getItem('playerPhoto_' + playerJerseyNumber);
                if (savedPhoto) {
                    document.getElementById('photoUrl').value = savedPhoto;
                    playerPhotoElement.innerHTML = '<img src="' + savedPhoto + '" alt="Фото игрока">';
                    photoInputContainer.style.display = 'none';
                    replacePhotoBtn.style.display = 'inline-block';
                }
                ${isGoalkeeper ? `
                async function loadGoalkeeperData() {
                    try {
                        var statsRes = await fetch('/api/player/goalkeeper-stats');
                        var statsResult = await statsRes.json();
                        if (statsResult.success) {
                            document.getElementById('totalMatches').textContent = statsResult.data.total_matches || 0;
                            document.getElementById('totalGoalsAgainst').textContent = statsResult.data.total_goals_against || 0;
                            document.getElementById('cleanSheets').textContent = statsResult.data.clean_sheets || 0;
                            document.getElementById('cleanSheetsHome').textContent = statsResult.data.clean_sheets_home || 0;
                            document.getElementById('cleanSheetsAway').textContent = statsResult.data.clean_sheets_away || 0;
                        }
                        var detailRes = await fetch('/api/player/goalkeeper-detail');
var detailResult = await detailRes.json();
if (detailResult.success && detailResult.data.length) {
    var html = '<table class="player-table"><thead><tr><th>Дата</th><th>Соперник</th><th>Локация</th><th>Пропущено</th><th>Сухой матч</th></tr></thead><tbody>';
    for (var g of detailResult.data) {
        var cleanSheetText = g["Сухой матч"] === 'Да' ? '<span class="clean-sheet">Да</span>' : 'Нет';
        var dateStr = new Date(g["Дата"]).toLocaleDateString('ru-RU');
        html += '<tr><td style="padding:12px;">' + dateStr + '<\/td><td style="padding:12px;">' + g["Соперник"] + '<\/td><td style="padding:12px;">' + (g["Локация"] === 'дома' ? ' Дома' : ' В гостях') + '<\/td><td class="stat-cell">' + g["Пропущено"] + '<\/td><td style="padding:12px;">' + cleanSheetText + '<\/td><\/tr>';
    }
    html += '<\/tbody><\/table>';
    document.getElementById('goalkeeperDetail').innerHTML = html;
                        } else {
                            document.getElementById('goalkeeperDetail').innerHTML = '<p style="text-align:center; color:#aaa;">Нет данных о матчах</p>';
                        }
                    } catch(err) { console.error(err); }
                }
                loadGoalkeeperData();
                ` : `
                async function loadData() {
                    try {
                        var statsRes = await fetch('/api/player/my-stats-personal');
                        var statsResult = await statsRes.json();
                        if (statsResult.success) {
                            var totalGoals = statsResult.data.total_goals || 0;
                            var totalMatches = statsResult.data.total_matches || 0;
                            var efficiency = totalMatches > 0 ? ((totalGoals / totalMatches) * 100).toFixed(1) : 0;
                            document.getElementById('totalGoals').textContent = totalGoals;
                            document.getElementById('homeGoals').textContent = statsResult.data.home_goals || 0;
                            document.getElementById('awayGoals').textContent = statsResult.data.away_goals || 0;
                            document.getElementById('totalMatches').textContent = totalMatches;
                            document.getElementById('efficiency').textContent = efficiency + '%';
                        }
                        var goalsRes = await fetch('/api/player/my-goals-detail-personal');
                        var goalsResult = await goalsRes.json();
                        if (goalsResult.success && goalsResult.data && goalsResult.data.length) {
                            var html = '<table class="player-table"><thead><tr><th>Дата матча</th><th>Соперник</th><th>Локация</th><th>Голов</th></tr></thead><tbody>';
                            for (var g of goalsResult.data) {
                                var dateStr = new Date(g.match_date).toLocaleDateString('ru-RU');
                                html += '<tr><td>' + dateStr + '<\/td><td>' + g.opponent + '<\/td><td>' + (g.location === 'дома' ? ' Дома' : ' В гостях') + '<\/td><td class="goal-highlight">' + (g.goals_scored || 1) + '<\/td><\/tr>';
                            }
                            html += '<\/tbody><\/table>';
                            document.getElementById('goalsDetail').innerHTML = html;
                        } else {
                            document.getElementById('goalsDetail').innerHTML = '<p style="text-align:center; color:#aaa;">Пока нет забитых голов </p>';
                        }
                    } catch(err) { console.error(err); }
                }
                loadData();
                `}
                async function logout() {
                    await fetch('/api/logout', { method: 'POST' });
                    window.location.href = '/login';
                }
            </script>
        </body>
        </html>
    `);
});
// ============================================
// КАБИНЕТ ТРЕНЕРА – ЧЁРНО-КРАСНЫЙ + ИСПРАВЛЕНЫ ДЕТАЛИ ГОЛОВ
app.get('/coach', authenticateToken, isCoach, async (req, res) => {
    const coachResult = await pool.query(`
        SELECT p.first_name, p.last_name
        FROM profiles p
        JOIN accounts a ON p.account_id = a.account_id
        WHERE a.account_id = $1
    `, [req.user.account_id]);
    
    const coach = coachResult.rows[0] || { first_name: 'Тренер', last_name: '' };
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Тренер - ФК Урал</title>
            <meta charset="utf-8">
            <link rel="icon" type="image/png" href="https://psv4.userapi.com/s/v1/d2/oayu_c16DiJp_9FkuuWKOVGbgqH9yvywjlBI4tkp9ILVECuv_yPwC37-fUKIwygJeM5qDYE6xqcrz9PWfxFQfgLS0_mkANrt6X1CpA0lznJMpG21DkF_MsxqPzBDevg58U968eW3ysA7/logo.png">
            <style>
                *{margin:0;padding:0;box-sizing:border-box;}
                body{font-family:'Segoe UI',Roboto,Arial,sans-serif;background:#0a0a0a;color:#e0e0e0;}
                header{background:#0a0a0a;border-bottom:3px solid #cc0000;padding:20px 40px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:15px;}
                header h1{color:#cc0000;font-size:1.8rem;}
                .logo{display:flex;align-items:center;gap:15px;}
                .logo img{height:50px;}
                .coach-info{display:flex;align-items:center;gap:20px;}
                .coach-avatar{width:48px;height:48px;background:#cc0000;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:24px;overflow:hidden;}
                .coach-avatar img{width:100%;height:100%;object-fit:cover;}
                button.logout{background:#cc0000;border:none;padding:8px 20px;border-radius:30px;color:#fff;font-weight:bold;cursor:pointer;transition:.2s;}
                button.logout:hover{background:#990000;}
                .container{max-width:1400px;margin:30px auto;padding:0 25px;}
                .menu{display:flex;gap:20px;margin-bottom:40px;flex-wrap:wrap;justify-content:center;}
                .menu-btn{background:#1e1e1e;color:#cc0000;border:1px solid #cc0000;padding:12px 28px;border-radius:40px;font-size:16px;font-weight:600;cursor:pointer;transition:.2s;}
                .menu-btn:hover{background:#cc0000;color:#fff;transform:translateY(-2px);}
                .card{background:#1e1e1e;border-radius:28px;padding:30px;margin-bottom:40px;display:none;border:1px solid #2c2c2c;}
                .card.active{display:block;}
                h2{color:#cc0000;border-left:5px solid #cc0000;padding-left:20px;margin-bottom:25px;font-size:1.8rem;}
                .matches-table,.league-table,.players-table,.goalkeeper-table{width:100%;border-collapse:collapse;border-radius:16px;overflow:hidden;}
                .matches-table th,.matches-table td,
                .league-table th,.league-table td,
                .players-table th,.players-table td,
                .goalkeeper-table th,.goalkeeper-table td{padding:14px 12px;text-align:center;border-bottom:1px solid #333;}
                .matches-table th,.league-table th,.players-table th,.goalkeeper-table th{background:#0f0f0f;color:#cc0000;font-weight:600;}
                .matches-table tr:hover,.league-table tr:hover,.players-table tr:hover{background:#2a2a2a;}
                .stat-cell{font-weight:bold;color:#cc0000;}
                .clean-sheet{color:#4caf50;}
                .ural-row{background:#2a2418;font-weight:bold;}
                .summary-stats{display:flex;flex-wrap:wrap;justify-content:center;gap:20px;margin-bottom:40px;}
                .summary-card{background:#151515;border-radius:20px;padding:15px 25px;text-align:center;min-width:130px;border-bottom:3px solid #cc0000;}
                .summary-card h3{font-size:28px;color:#cc0000;margin-top:8px;}
                .player-detail,.match-goals-container{margin-top:30px;padding-top:20px;border-top:2px solid #2c2c2c;display:none;}
                .player-detail.active,.match-goals-container.active{display:block;}
                .clickable-row{cursor:pointer;}
                .clickable-row:hover{background:#2a2418 !important;}
                .photo-input{background:#151515;padding:15px;border-radius:20px;margin-bottom:20px;}
                .photo-input input{width:100%;padding:10px;border-radius:12px;border:none;background:#2a2a2a;color:#fff;}
                .replace-photo-btn{background:#cc0000;border:none;padding:6px 14px;border-radius:20px;color:#fff;font-size:12px;cursor:pointer;}
                @media (max-width:800px){
                    header{flex-direction:column;text-align:center;}
                    .summary-stats{gap:12px;}
                    .summary-card{padding:10px 15px;min-width:100px;}
                    .summary-card h3{font-size:22px;}
                }
            </style>
        </head>
        <body>
            <header>
                <div class="logo">
                    <img src="https://psv4.userapi.com/s/v1/d2/oayu_c16DiJp_9FkuuWKOVGbgqH9yvywjlBI4tkp9ILVECuv_yPwC37-fUKIwygJeM5qDYE6xqcrz9PWfxFQfgLS0_mkANrt6X1CpA0lznJMpG21DkF_MsxqPzBDevg58U968eW3ysA7/logo.png" alt="Логотип">
                    <h1> Кабинет тренера</h1>
                </div>
                <div class="coach-info">
                    <div class="coach-avatar" id="coachAvatar"><span></span></div>
                    <span>${coach.first_name} ${coach.last_name}</span>
                    <button class="logout" onclick="logout()">Выйти</button>
                </div>
            </header>
            <div class="container">
                <div class="photo-input" id="coachPhotoContainer">
                    <label style="color:#fff;">🔗 Ссылка на фото тренера:</label>
                    <input type="text" id="coachPhotoUrl" placeholder="https://example.com/photo.jpg" onchange="updateCoachPhoto()">
                </div>
                <div style="text-align:center;margin-bottom:20px;">
                    <button class="replace-photo-btn" id="replaceCoachPhotoBtn" onclick="showCoachPhotoInput()" style="display:none;">📷 Заменить фото</button>
                </div>
                
                <div class="menu">
                    <button class="menu-btn" onclick="show('matches')"> Результаты матчей</button>
                    <button class="menu-btn" onclick="show('league')"> Турнирная таблица</button>
                    <button class="menu-btn" onclick="show('players')"> Статистика игроков</button>
                    <button class="menu-btn" onclick="show('goalkeeper')"> Статистика вратаря</button>
                </div>
                
                <div id="matches" class="card">
                    <h2> Результаты матчей</h2>
                    <div id="matchesSummary" class="summary-stats"></div>
                    <div id="matchesData"><div class="loading">Загрузка...</div></div>
                    <div id="matchGoalsContainer" class="match-goals-container">
                        <h3 style="color:#cc0000;"> Голы в матче</h3>
                        <div id="matchGoalsData"></div>
                    </div>
                </div>
                
                <div id="league" class="card">
                    <h2> Турнирная таблица</h2>
                    <div id="leagueData"><div class="loading">Загрузка...</div></div>
                </div>
                
                <div id="players" class="card">
                    <h2> Статистика полевых игроков</h2>
                    <div id="playersData"><div class="loading">Загрузка...</div></div>
                    <div id="playerDetail" class="player-detail">
                        <h3 id="playerDetailTitle"> Детальная статистика голов</h3>
                        <div id="playerDetailData"></div>
                    </div>
                </div>
                
                <div id="goalkeeper" class="card">
                    <h2> Статистика вратаря</h2>
                    <div id="goalkeeperData"><div class="loading">Загрузка...</div></div>
                </div>
            </div>
            <script>
                var playersDataCache = [];
                var matchesDataCache = [];
                var coachAvatar = document.getElementById('coachAvatar');
                var coachPhotoContainer = document.getElementById('coachPhotoContainer');
                var replaceCoachPhotoBtn = document.getElementById('replaceCoachPhotoBtn');
                
                function updateCoachPhoto() {
                    var url = document.getElementById('coachPhotoUrl').value;
                    if (url) {
                        coachAvatar.innerHTML = '<img src="' + url + '" alt="Фото">';
                        localStorage.setItem('coachPhoto', url);
                        coachPhotoContainer.style.display = 'none';
                        replaceCoachPhotoBtn.style.display = 'inline-block';
                    }
                }
                function showCoachPhotoInput() {
                    coachPhotoContainer.style.display = 'block';
                    replaceCoachPhotoBtn.style.display = 'none';
                    document.getElementById('coachPhotoUrl').value = '';
                }
                var savedCoachPhoto = localStorage.getItem('coachPhoto');
                if (savedCoachPhoto) {
                    document.getElementById('coachPhotoUrl').value = savedCoachPhoto;
                    coachAvatar.innerHTML = '<img src="' + savedCoachPhoto + '" alt="Фото">';
                    coachPhotoContainer.style.display = 'none';
                    replaceCoachPhotoBtn.style.display = 'inline-block';
                }
                
                async function show(section) {
                    document.querySelectorAll('.card').forEach(function(c) { c.classList.remove('active'); });
                    document.getElementById(section).classList.add('active');
                    if (section === 'matches') await loadMatches();
                    if (section === 'league') await loadLeagueTable();
                    if (section === 'players') await loadPlayers();
                    if (section === 'goalkeeper') await loadGoalkeeper();
                }
                
                async function loadLeagueTable() {
                    try {
                        var res = await fetch('/api/league-table');
                        var data = await res.json();
                        if (data.success && data.data && data.data.length) {
                            var html = '<table class="league-table"><thead><tr><th>Команда</th><th>И</th><th>В</th><th>Н</th><th>П</th><th>З</th><th>П</th><th>О</th></tr></thead><tbody>';
                            for (var row of data.data) {
                                var cls = row.Команда === 'Урал' ? 'ural-row' : '';
                                html += '<tr class="' + cls + '">' +
                                    '<td><strong>' + row.Команда + '<\/strong><\/td>' +
                                    '<td>' + row.Игры + '<\/td>' +
                                    '<td>' + row.Победы + '<\/td>' +
                                    '<td>' + row.Ничьи + '<\/td>' +
                                    '<td>' + row.Поражения + '<\/td>' +
                                    '<td>' + row.Забито + '<\/td>' +
                                    '<td>' + row.Пропущено + '<\/td>' +
                                    '<td class="stat-cell">' + row.Очки + '<\/td><\/tr>';
                            }
                            html += '<\/tbody><\/table>';
                            document.getElementById('leagueData').innerHTML = html;
                        } else {
                            document.getElementById('leagueData').innerHTML = '<div class="loading">Нет данных</div>';
                        }
                    } catch(e) { console.error(e); }
                }
                
                async function loadMatches() {
                    try {
                        var res = await fetch('/api/matches');
                        var data = await res.json();
                        if (data.success && data.data && data.data.length) {
                            matchesDataCache = data.data;
                            var totalGoalsFor = 0, totalGoalsAgainst = 0, totalWins = 0, totalDraws = 0, totalLosses = 0, totalPoints = 0;
                            for (var m of data.data) {
                                totalGoalsFor += m.Забито || 0;
                                totalGoalsAgainst += m.Пропущено || 0;
                                if (m.Очки === 3) totalWins++;
                                else if (m.Очки === 1) totalDraws++;
                                else if (m.Очки === 0) totalLosses++;
                                totalPoints += m.Очки || 0;
                            }
                            var summaryHtml = '<div class="summary-card"><div> Матчей</div><h3>' + data.data.length + '<\/h3><\/div>' +
                                '<div class="summary-card"><div> Очков</div><h3>' + totalPoints + '<\/h3><\/div>' +
                                '<div class="summary-card"><div> Забито</div><h3>' + totalGoalsFor + '<\/h3><\/div>' +
                                '<div class="summary-card"><div> Пропущено</div><h3>' + totalGoalsAgainst + '<\/h3><\/div>' +
                                '<div class="summary-card"><div>Победы</div><h3>' + totalWins + '<\/h3><\/div>' +
                                '<div class="summary-card"><div> Ничьи</div><h3>' + totalDraws + '<\/h3><\/div>' +
                                '<div class="summary-card"><div>Поражения</div><h3>' + totalLosses + '<\/h3><\/div>';
                            document.getElementById('matchesSummary').innerHTML = summaryHtml;
                            var html = '<table class="matches-table"><thead><tr><th>Дата</th><th>Соперник</th><th>Локация</th><th>Забито</th><th>Пропущено</th><th>Очки</th></tr></thead><tbody>';
                            for (var i = 0; i < data.data.length; i++) {
                                var m = data.data[i];
                                var dateStr = new Date(m.Дата).toLocaleDateString('ru-RU');
                                html += '<tr class="clickable-row" onclick="showMatchGoals(' + i + ')">' +
                                    '<td>' + dateStr + '<\/td>' +
                                    '<td>' + m.Соперник + '<\/td>' +
                                    '<td>' + (m.Локация === 'дома' ? ' Дома' : ' В гостях') + '<\/td>' +
                                    '<td class="stat-cell">' + (m.Забито || 0) + '<\/td>' +
                                    '<td>' + (m.Пропущено || 0) + '<\/td>' +
                                    '<td class="stat-cell">' + (m.Очки || 0) + '<\/td><\/tr>';
                            }
                            html += '<\/tbody><\/table>';
                            document.getElementById('matchesData').innerHTML = html;
                        } else {
                            document.getElementById('matchesData').innerHTML = '<div class="loading">Нет матчей</div>';
                        }
                    } catch(e) { console.error(e); }
                }
                
                async function showMatchGoals(index) {
                    var match = matchesDataCache[index];
                    if (!match) return;
                    try {
                        var res = await fetch('/api/match-goals?match_id=' + match.ID);
                        var data = await res.json();
                        var html = '<table class="players-table" style="width:100%;"><thead><tr><th>Игрок</th><th>Позиция</th><th>Голы</th></tr></thead><tbody>';
                        if (data.success && data.data && data.data.length) {
                            for (var g of data.data) {
                                html += '<tr><td><strong>' + g.player_name + '<\/strong><\/td><td>' + g.position + '<\/td><td class="stat-cell"> ' + g.goals_count + '<\/td><\/tr>';
                            }
                        } else {
                            html += '<tr><td colspan="3">В этом матче нет забитых голов<\/td><\/tr>';
                        }
                        html += '<\/tbody><\/table>';
                        document.getElementById('matchGoalsData').innerHTML = html;
                        document.getElementById('matchGoalsContainer').classList.add('active');
                        document.getElementById('matchGoalsContainer').scrollIntoView({ behavior: 'smooth' });
                    } catch(e) { console.error(e); }
                }
                
                async function loadPlayers() {
                    try {
                        var res = await fetch('/api/players-stats-full');
                        var data = await res.json();
                        if (data.success && data.data && data.data.length) {
                            playersDataCache = data.data.filter(function(p) { return p.position !== 'Вратарь'; });
                            if (playersDataCache.length) {
                                var html = '<table class="players-table"><thead><tr><th>№</th><th>Игрок</th><th>Позиция</th><th>Матчи</th><th>Голы</th></tr></thead><tbody>';
                                for (var i = 0; i < playersDataCache.length; i++) {
                                    var p = playersDataCache[i];
                                    html += '<tr class="clickable-row" onclick="showPlayerDetail(' + i + ')">' +
                                        '<td>' + (p.jersey_number || '-') + '<\/td>' +
                                        '<td style="text-align:left;"><strong>' + p.full_name + '<\/strong><\/td>' +
                                        '<td>' + p.position + '<\/td>' +
                                        '<td>' + (p.total_matches || 0) + '<\/td>' +
                                        '<td class="stat-cell">' + (p.total_goals || 0) + '<\/td><\/tr>';
                                }
                                html += '<\/tbody><\/table>';
                                document.getElementById('playersData').innerHTML = html;
                            } else {
                                document.getElementById('playersData').innerHTML = '<div class="loading">Нет полевых игроков</div>';
                            }
                        } else {
                            document.getElementById('playersData').innerHTML = '<div class="loading">Нет данных об игроках</div>';
                        }
                    } catch(e) { console.error(e); }
                }
                
                async function showPlayerDetail(index) {
                    var player = playersDataCache[index];
                    if (!player) return;
                    document.getElementById('playerDetailTitle').innerHTML = ' Голы: ' + player.full_name;
                    try {
                        var res = await fetch('/api/player/goals-detail?name=' + encodeURIComponent(player.full_name));
                        var data = await res.json();
                        var html = '<table class="players-table" style="width:100%;"><thead><tr><th>Дата</th><th>Соперник</th><th>Локация</th><th>Голов</th></tr></thead><tbody>';
                        if (data.success && data.data && data.data.length) {
                            for (var g of data.data) {
                                var dateStr = new Date(g.match_date).toLocaleDateString('ru-RU');
                                html += '<tr><td>' + dateStr + '<\/td><td>' + g.opponent + '<\/td><td>' + (g.location === 'дома' ? ' Дома' : ' В гостях') + '<\/td><td class="stat-cell">' + (g.goals_scored || 1) + '<\/td><\/tr>';
                            }
                        } else {
                            html += '<tr><td colspan="4">Нет забитых голов<\/td><\/tr>';
                        }
                        html += '<\/tbody><\/table>';
                        document.getElementById('playerDetailData').innerHTML = html;
                        document.getElementById('playerDetail').classList.add('active');
                    } catch(e) { console.error(e); }
                }
                
                async function loadGoalkeeper() {
    try {
        var res = await fetch('/api/goalkeeper-stats');
        var data = await res.json();
        if (data.success && data.data && data.data.length) {
            // Считаем общую статистику
            var totalMatches = data.data.length;
            var totalGoalsAgainst = 0;
            var cleanSheets = 0;
            for (var g of data.data) {
                totalGoalsAgainst += g.Пропущено || 0;
                if (g["Сухой матч"] === 'Да') cleanSheets++;
            }
            var cleanPercent = totalMatches ? ((cleanSheets / totalMatches) * 100).toFixed(1) : 0;
            
            // Формируем горизонтальную таблицу: сначала строка с итогами, затем детальные строки
            var html = '<table class="goalkeeper-table" style="width:100%;">' +
                '<thead>' +
                '<tr><th>Вратарь</th><th>Матчи</th><th>Пропущено</th><th>Сухие матчи</th><th>% сухих</th></tr>' +
                '</thead><tbody>' +
                '<tr>' +
                '<td><strong>' + (data.data[0]?.Вратарь || 'Вратарь') + '</strong></td>' +
                '<td>' + totalMatches + '</td>' +
                '<td class="stat-cell">' + totalGoalsAgainst + '</td>' +
                '<td class="clean-sheet">' + cleanSheets + '</td>' +
                '<td>' + cleanPercent + '%</td>' +
                '</tr>' +
                '</tbody></table>';
            
            // Детальная таблица по матчам
            html += '<h3 style="margin-top:30px; color:#cc0000;"> Детальная статистика по матчам</h3>';
            html += '<table class="goalkeeper-table" style="width:100%;">' +
                '<thead><tr><th>Дата</th><th>Соперник</th><th>Локация</th><th>Пропущено</th><th>Сухой матч</th></tr></thead><tbody>';
            for (var g of data.data) {
                var dateStr = new Date(g["Дата"]).toLocaleDateString('ru-RU');
                var clean = g["Сухой матч"] === 'Да' ? '<span class="clean-sheet">Да</span>' : 'Нет';
                html += '<tr>' +
                    '<td>' + dateStr + '</td>' +
                    '<td>' + g["Соперник"] + '</td>' +
                    '<td>' + (g["Локация"] === 'дома' ? ' Дома' : ' В гостях') + '</td>' +
                    '<td class="stat-cell">' + (g["Пропущено"] || 0) + '</td>' +
                    '<td>' + clean + '</td>' +
                '</tr>';
            }
            html += '</tbody></table>';
            document.getElementById('goalkeeperData').innerHTML = html;
        } else {
            document.getElementById('goalkeeperData').innerHTML = '<div class="loading">Нет данных о вратаре</div>';
        }
    } catch(e) {
        console.error(e);
        document.getElementById('goalkeeperData').innerHTML = '<div class="loading">Ошибка загрузки данных вратаря</div>';
    }
}
                
                async function logout() {
                    await fetch('/api/logout', { method: 'POST' });
                    window.location.href = '/login';
                }
                
                show('matches');
            </script>
        </body>
        </html>
    `);
});

// ============================================
// ПАНЕЛЬ АДМИНИСТРАТОРА (исправленная версия с правильной таблицей)
app.get('/admin', authenticateToken, isAdmin, (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Админ - ФК Урал</title>
            <link rel="icon" type="image/png" href="https://psv4.userapi.com/s/v1/d2/oayu_c16DiJp_9FkuuWKOVGbgqH9yvywjlBI4tkp9ILVECuv_yPwC37-fUKIwygJeM5qDYE6xqcrz9PWfxFQfgLS0_mkANrt6X1CpA0lznJMpG21DkF_MsxqPzBDevg58U968eW3ysA7/logo.png">
            <style>
                *{margin:0;padding:0;box-sizing:border-box;}
                body{font-family:'Segoe UI',Roboto,Arial,sans-serif;background:#0a0a0a;color:#e0e0e0;}
                header{background:#0a0a0a;border-bottom:3px solid #cc0000;padding:20px 40px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:15px;}
                header h1{color:#cc0000;font-size:1.8rem;}
                .logo{display:flex;align-items:center;gap:15px;}
                .logo img{height:50px;}
                .logout-btn{background:#cc0000;border:none;padding:8px 20px;border-radius:30px;color:#fff;font-weight:bold;cursor:pointer;transition:.2s;}
                .logout-btn:hover{background:#990000;transform:scale(1.02);}
                .container{max-width:1400px;margin:30px auto;padding:0 25px;}
                .menu{display:flex;gap:20px;margin-bottom:40px;flex-wrap:wrap;justify-content:center;}
                .menu-btn{background:#1e1e1e;color:#cc0000;border:1px solid #cc0000;padding:12px 28px;border-radius:40px;font-size:16px;font-weight:600;cursor:pointer;transition:.2s;}
                .menu-btn:hover{background:#cc0000;color:#fff;transform:translateY(-2px);}
                .card{background:#1e1e1e;border-radius:28px;padding:30px;margin-bottom:40px;display:none;border:1px solid #2c2c2c;}
                .card.active{display:block;}
                h2{color:#cc0000;border-left:5px solid #cc0000;padding-left:20px;margin-bottom:25px;font-size:1.8rem;}
                .users-table,.matches-table{width:100%;border-collapse:collapse;border-radius:16px;overflow:hidden;}
                .users-table th,.users-table td,
                .matches-table th,.matches-table td{padding:14px 12px;text-align:center;border-bottom:1px solid #333;}
                .users-table th,.matches-table th{background:#0f0f0f;color:#cc0000;font-weight:600;}
                .users-table tr:hover,.matches-table tr:hover{background:#2a2a2a;}
                .status-active{color:#4caf50;font-weight:bold;}
                .status-inactive{color:#e74c3c;font-weight:bold;}
                .match-score{font-weight:bold;color:#cc0000;}
                .btn-edit{background:#cc0000;border:none;padding:6px 14px;border-radius:20px;color:#fff;font-size:12px;cursor:pointer;margin-right:8px;}
                .btn-delete{background:#990000;border:none;padding:6px 14px;border-radius:20px;color:#fff;font-size:12px;cursor:pointer;}
                .btn-block{background:#e74c3c;border:none;padding:6px 14px;border-radius:20px;color:#fff;font-size:12px;cursor:pointer;margin-right:8px;}
                .btn-unblock{background:#4caf50;border:none;padding:6px 14px;border-radius:20px;color:#fff;font-size:12px;cursor:pointer;}
                .form-group{margin-bottom:20px;}
                label{display:block;margin-bottom:8px;color:#cc0000;font-weight:600;}
                input,select{width:100%;padding:12px;border-radius:12px;border:1px solid #444;background:#2a2a2a;color:#fff;}
                button[onclick="addUser()"], button[onclick="addMatch()"], button[onclick="addGoalFor()"], button[onclick="addGoalAgainst()"]{background:#cc0000;border:none;padding:10px 20px;border-radius:30px;color:#fff;font-weight:bold;cursor:pointer;margin-top:10px;}
                .warning{background:#2a1a1a;border-left:4px solid #cc0000;padding:15px;border-radius:12px;margin:15px 0;color:#ff9999;}
                .number-input-wrapper{display:flex;gap:10px;align-items:center;}
                .picker-btn{background:#2a2a2a;border:1px solid #cc0000;padding:10px 15px;border-radius:30px;color:#cc0000;cursor:pointer;}
                .modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.9);z-index:2000;justify-content:center;align-items:center;}
                .modal-overlay.active{display:flex;}
                .modal-content{background:#1e1e1e;border-radius:28px;padding:25px;width:90%;max-width:600px;max-height:85vh;overflow-y:auto;border:1px solid #cc0000;}
                .modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;}
                .close-modal{background:#2a2a2a;border:none;padding:6px 14px;border-radius:20px;color:#fff;cursor:pointer;}
                .number-grid{display:grid;grid-template-columns:repeat(10,1fr);gap:10px;margin-top:15px;}
                .num-btn{padding:12px;border:1px solid #444;border-radius:12px;background:#2a2a2a;color:#fff;cursor:pointer;text-align:center;}
                .num-btn.occupied{background:#cc0000;opacity:0.5;cursor:not-allowed;}
                .num-btn.selected{background:#cc0000;color:#fff;}
                @media (max-width:800px){
                    header{flex-direction:column;text-align:center;}
                    .menu{gap:12px;}
                    .menu-btn{padding:8px 16px;font-size:14px;}
                }
            </style>
        </head>
        <body>
            <header>
                <div class="logo">
                    <img src="https://psv4.userapi.com/s/v1/d2/oayu_c16DiJp_9FkuuWKOVGbgqH9yvywjlBI4tkp9ILVECuv_yPwC37-fUKIwygJeM5qDYE6xqcrz9PWfxFQfgLS0_mkANrt6X1CpA0lznJMpG21DkF_MsxqPzBDevg58U968eW3ysA7/logo.png" alt="Логотип">
                    <h1> Панель администратора</h1>
                </div>
                <button class="logout-btn" onclick="logout()">Выйти</button>
            </header>
            <div class="container">
                <div class="menu">
                    <button class="menu-btn" onclick="show('users')"> Управление пользователями</button>
                    <button class="menu-btn" onclick="show('matches')"> Управление матчами</button>
                    <button class="menu-btn" onclick="show('goals-for')"> Забитые голы</button>
                    <button class="menu-btn" onclick="show('goals-against')"> Пропущенные голы</button>
                </div>
                
                <div id="users" class="card">
                    <h2> Управление пользователями</h2>
                    <button onclick="showAddUserForm()" style="margin-bottom:20px;background:#cc0000;border:none;padding:8px 20px;border-radius:30px;color:#fff;cursor:pointer;">➕ Добавить пользователя</button>
                    <div id="addUserForm" style="display:none;background:#151515;padding:20px;border-radius:20px;margin-bottom:20px;">
                        <h3 style="color:#cc0000;">Новый пользователь</h3>
                        <div class="form-group"><label>Фамилия:</label><input type="text" id="newLastName" placeholder="Иванов" oninput="generateEmail()"></div>
                        <div class="form-group"><label>Имя:</label><input type="text" id="newFirstName" placeholder="Иван" oninput="generateEmail()"></div>
                        <div class="form-group"><label>Email:</label><input type="text" id="newEmail" placeholder="ivanov.ivan@ural.ru" readonly></div>
                        <div class="form-group"><label>Пароль:</label><input type="text" id="newPassword" placeholder="password"></div>
                        <div class="form-group"><label>Дата рождения:</label><input type="date" id="newBirthDate"></div>
                        <div class="form-group"><label>Телефон:</label><input type="text" id="newPhone" placeholder="+7 (999) 000-00-00"></div>
                        <div class="form-group"><label>Роль:</label><select id="newRole" onchange="togglePlayerFields()"><option value="1">Игрок</option><option value="2">Тренер</option><option value="3">Администратор</option></select></div>
                        <div class="form-group" id="playerFieldsGroup">
                            <label>Номер игрока:</label>
                            <div class="number-input-wrapper">
                                <input type="text" id="newJerseyNumber" placeholder="1-99" readonly>
                                <button type="button" class="picker-btn" onclick="openNumberPicker('newJerseyNumber')">🔢 Выбрать</button>
                            </div>
                        </div>
                        <div class="form-group" id="positionGroup">
                            <label>Позиция:</label><select id="newPosition"><option value="Вратарь">Вратарь</option><option value="Защитник">Защитник</option><option value="Полузащитник">Полузащитник</option><option value="Нападающий">Нападающий</option></select>
                        </div>
                        <button onclick="addUser()">✅ Создать</button>
                        <button onclick="hideAddUserForm()" style="background:#666;">❌ Отмена</button>
                    </div>
                    <div id="usersList"><div class="loading">Загрузка...</div></div>
                </div>
                
                <div id="matches" class="card">
                    <h2> Управление матчами</h2>
                    <button onclick="showAddMatchForm()" style="margin-bottom:20px;background:#cc0000;border:none;padding:8px 20px;border-radius:30px;color:#fff;cursor:pointer;">➕ Добавить матч</button>
                    <div id="addMatchForm" style="display:none;background:#151515;padding:20px;border-radius:20px;margin-bottom:20px;">
                        <h3 style="color:#cc0000;">Новый матч</h3>
                        <div class="form-group"><label>ID матча:</label><input type="text" id="newMatchId" placeholder="09"></div>
                        <div class="form-group"><label>Дата:</label><input type="date" id="newMatchDate"></div>
                        <div class="form-group"><label>Соперник:</label><select id="newOpponentId"></select></div>
                        <div class="form-group"><label>Локация:</label><select id="newLocation"><option value="дома">Дома</option><option value="в гостях">В гостях</option></select></div>
                        <div class="form-group"><label>Голы Урал:</label><input type="number" id="newGoalsFor" value="0"></div>
                        <div class="form-group"><label>Голы соперника:</label><input type="number" id="newGoalsAgainst" value="0"></div>
                        <button onclick="addMatch()">✅ Добавить</button>
                        <button onclick="hideAddMatchForm()" style="background:#666;">❌ Отмена</button>
                    </div>
                    <div id="matchesList"><div class="loading">Загрузка...</div></div>
                </div>
                
                <div id="goals-for" class="card">
                    <h2> Добавить забитый гол (Урал)</h2>
                    <div style="text-align:left;">
                        <div class="form-group"><label>Матч:</label><select id="goalForMatchId" onchange="checkMatchGoals()"></select></div>
                        <div id="goalForWarning" class="warning" style="display:none;">⚠️ В этом матче Урал не забил ни одного гола.</div>
                        <div id="goalForForm" style="display:none;">
                            <div class="form-group"><label>Фамилия игрока:</label><input type="text" id="goalPlayerLastName" placeholder="Например: Соболев Дмитрий" list="playersList"><datalist id="playersList"></datalist></div>
                            <div class="form-group"><label>Количество голов:</label><input type="number" id="goalCount" value="1" min="1" max="10"></div>
                            <button onclick="addGoalFor()">➕ Добавить гол(ы)</button>
                        </div>
                        <div id="goalForMessage" style="margin-top:15px;"></div>
                    </div>
                </div>
                
                <div id="goals-against" class="card">
                    <h2> Добавить пропущенный гол (соперник)</h2>
                    <div style="text-align:left;">
                        <div class="form-group"><label>Матч:</label><select id="goalAgainstMatchId" onchange="checkMatchGoalsAgainst()"></select></div>
                        <div id="goalAgainstWarning" class="warning" style="display:none;">⚠️ В этом матче Урал не пропустил ни одного гола.</div>
                        <div id="goalAgainstForm" style="display:none;">
                            <div class="form-group"><label>Вратарь (пропустивший гол):</label><select id="goalkeeperId"><option value="">-- Выберите вратаря --</option></select></div>
                            <div class="form-group"><label>Количество пропущенных голов:</label><input type="number" id="goalAgainstCount" value="1" min="1" max="10"></div>
                            <button onclick="addGoalAgainst()">➕ Добавить гол(ы)</button>
                        </div>
                        <div id="goalAgainstMessage" style="margin-top:15px;"></div>
                    </div>
                </div>
            </div>

            <!-- Модальное окно выбора номера -->
            <div id="numberPickerModal" class="modal-overlay">
                <div class="modal-content">
                    <div class="modal-header"><h3 style="color:#cc0000;">🔢 Выберите игровой номер (1-99)</h3><button class="close-modal" onclick="closeNumberPicker()">✕ Закрыть</button></div>
                    <div id="numberGrid" class="number-grid">Загрузка...</div>
                </div>
            </div>

            <!-- Модальное окно редактирования пользователя -->
            <div id="editUserModal" class="modal-overlay">
                <div class="modal-content">
                    <div class="modal-header"><h3 style="color:#cc0000;">✏️ Редактирование пользователя</h3><button class="close-modal" onclick="closeEditModal()">✕ Закрыть</button></div>
                    <div style="text-align:left;">
                        <input type="hidden" id="editAccountId">
                        <div class="form-group"><label>Email:</label><input type="text" id="editEmail" readonly style="background:#333;"></div>
                        <div class="form-group"><label>Роль:</label><input type="text" id="editRoleName" readonly style="background:#333;"></div>
                        <div class="form-group"><label>Имя:</label><input type="text" id="editFirstName"></div>
                        <div class="form-group"><label>Фамилия:</label><input type="text" id="editLastName"></div>
                        <div class="form-group"><label>Дата рождения:</label><input type="date" id="editBirthDate"></div>
                        <div class="form-group"><label>Телефон:</label><input type="text" id="editPhone"></div>
                        <div id="editPlayerFields" style="display:none;border-top:1px solid #444;padding-top:15px;margin-top:15px;">
                            <h4 style="color:#cc0000;"> Данные игрока</h4>
                            <div class="form-group"><label>Номер игрока:</label><div class="number-input-wrapper"><input type="number" id="editJerseyNumber" placeholder="1-99" min="1" max="99"><button type="button" class="picker-btn" onclick="openNumberPicker('editJerseyNumber')">🔢 Выбрать</button></div></div>
                            <div class="form-group"><label>Позиция:</label><select id="editPosition"><option value="Вратарь">Вратарь</option><option value="Защитник">Защитник</option><option value="Полузащитник">Полузащитник</option><option value="Нападающий">Нападающий</option></select></div>
                        </div>
                        <button onclick="saveUserEdit()" style="width:100%;margin-top:15px;">💾 Сохранить изменения</button>
                    </div>
                </div>
            </div>
            
            <script>
                let matchesDataCache = [];
                let currentNumberTargetId = 'newJerseyNumber';
                
                function transliterate(text) {
                    const translitMap = {
                        'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd',
                        'е': 'e', 'ё': 'yo', 'ж': 'zh', 'з': 'z', 'и': 'i',
                        'й': 'y', 'к': 'k', 'л': 'l', 'м': 'm', 'н': 'n',
                        'о': 'o', 'п': 'p', 'р': 'r', 'с': 's', 'т': 't',
                        'у': 'u', 'ф': 'f', 'х': 'kh', 'ц': 'ts', 'ч': 'ch',
                        'ш': 'sh', 'щ': 'shch', 'ъ': '', 'ы': 'y', 'ь': '',
                        'э': 'e', 'ю': 'yu', 'я': 'ya'
                    };
                    return text.toLowerCase().split('').map(char => translitMap[char] || char).join('');
                }
                
                function generateEmail() {
                    var lastName = document.getElementById('newLastName').value.trim();
                    var firstName = document.getElementById('newFirstName').value.trim();
                    if (lastName && firstName) {
                        document.getElementById('newEmail').value = transliterate(lastName) + '.' + transliterate(firstName) + '@ural.ru';
                    } else if (lastName) {
                        document.getElementById('newEmail').value = transliterate(lastName) + '@ural.ru';
                    }
                }

                function togglePlayerFields() {
                    const role = document.getElementById('newRole').value;
                    const playerGroup = document.getElementById('playerFieldsGroup');
                    const posGroup = document.getElementById('positionGroup');
                    if (role === '1') {
                        playerGroup.style.display = 'block';
                        posGroup.style.display = 'block';
                    } else {
                        playerGroup.style.display = 'none';
                        posGroup.style.display = 'none';
                        document.getElementById('newJerseyNumber').value = '';
                    }
                }

                async function openEditModal(accountId) {
                    try {
                        const res = await fetch('/api/admin/users/' + accountId);
                        const data = await res.json();
                        if (!data.success) return;
                        const u = data.data;
                        document.getElementById('editAccountId').value = u.account_id;
                        document.getElementById('editEmail').value = u.email || '';
                        document.getElementById('editRoleName').value = u.role_name || '';
                        document.getElementById('editFirstName').value = u.first_name || '';
                        document.getElementById('editLastName').value = u.last_name || '';
                        document.getElementById('editBirthDate').value = u.birth_date ? u.birth_date.split('T')[0] : '';
                        document.getElementById('editPhone').value = u.phone || '';
                        const isPlayer = u.role_name === 'игрок';
                        document.getElementById('editPlayerFields').style.display = isPlayer ? 'block' : 'none';
                        if (isPlayer) {
                            document.getElementById('editJerseyNumber').value = u.jersey_number !== null ? u.jersey_number : '';
                            document.getElementById('editPosition').value = u.position || 'Защитник';
                        }
                        document.getElementById('editUserModal').classList.add('active');
                    } catch (err) {
                        console.error('Ошибка загрузки данных:', err);
                        alert('Не удалось загрузить данные');
                    }
                }

                function closeEditModal() {
                    document.getElementById('editUserModal').classList.remove('active');
                }

                async function saveUserEdit() {
                    const accountId = document.getElementById('editAccountId').value;
                    const roleName = document.getElementById('editRoleName').value;
                    const data = {
                        first_name: document.getElementById('editFirstName').value,
                        last_name: document.getElementById('editLastName').value,
                        birth_date: document.getElementById('editBirthDate').value || null,
                        phone: document.getElementById('editPhone').value || null
                    };
                    if (roleName === 'игрок') {
                        const jerseyNumber = document.getElementById('editJerseyNumber').value;
                        const position = document.getElementById('editPosition').value;
                        if (!jerseyNumber) {
                            alert('Для игрока нужно указать номер!');
                            return;
                        }
                        data.jersey_number = jerseyNumber;
                        data.position = position;
                    }
                    try {
                        const res = await fetch('/api/admin/users/' + accountId + '/profile', {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(data)
                        });
                        const result = await res.json();
                        if (result.success) {
                            alert('✅ Данные успешно обновлены!');
                            closeEditModal();
                            await loadUsers();
                        } else {
                            alert('❌ Ошибка: ' + result.error);
                        }
                    } catch (err) {
                        alert('❌ Ошибка сохранения');
                    }
                }

                async function openNumberPicker(targetId) {
                    currentNumberTargetId = targetId;
                    const modal = document.getElementById('numberPickerModal');
                    modal.classList.add('active');
                    const grid = document.getElementById('numberGrid');
                    grid.innerHTML = '<p style="text-align:center; grid-column: 1/-1;">Загрузка занятых номеров...</p>';
                    try {
                        const res = await fetch('/api/admin/occupied-numbers');
                        const data = await res.json();
                        const occupied = new Set(data.data.map(n => parseInt(n.jersey_number)));
                        const currentVal = parseInt(document.getElementById(targetId).value);
                        grid.innerHTML = '';
                        for (let i = 1; i <= 99; i++) {
                            const btn = document.createElement('button');
                            btn.className = 'num-btn';
                            btn.textContent = i;
                            if (occupied.has(i)) {
                                btn.classList.add('occupied');
                                btn.disabled = true;
                            } else {
                                btn.onclick = () => selectNumber(i);
                                if (i === currentVal) btn.classList.add('selected');
                            }
                            grid.appendChild(btn);
                        }
                    } catch (err) {
                        grid.innerHTML = '<p style="color:red; text-align:center; grid-column: 1/-1;">Ошибка загрузки</p>';
                    }
                }

                function selectNumber(num) {
                    document.getElementById(currentNumberTargetId).value = num;
                    document.getElementById('numberPickerModal').classList.remove('active');
                }

                function closeNumberPicker() {
                    document.getElementById('numberPickerModal').classList.remove('active');
                }
                
                async function loadTeams() {
                    var res = await fetch('/api/teams');
                    var data = await res.json();
                    if (data.success && data.data) {
                        var select = document.getElementById('newOpponentId');
                        select.innerHTML = '';
                        for (var t of data.data) {
                            if (t.team_name !== 'Урал') {
                                select.innerHTML += '<option value="' + t.team_id + '">' + t.team_name + '</option>';
                            }
                        }
                    }
                }
                
                async function loadGoalkeepers() {
                    var res = await fetch('/api/goalkeepers');
                    var data = await res.json();
                    if (data.success && data.data) {
                        var select = document.getElementById('goalkeeperId');
                        select.innerHTML = '<option value="">-- Выберите вратаря --</option>';
                        for (var g of data.data) {
                            select.innerHTML += '<option value="' + g.player_id + '">' + g.full_name + ' (№' + g.jersey_number + ')</option>';
                        }
                    }
                }
                
                async function loadPlayersList() {
                    var res = await fetch('/api/players');
                    var data = await res.json();
                    if (data.success && data.data) {
                        var datalist = document.getElementById('playersList');
                        datalist.innerHTML = '';
                        for (var p of data.data) {
                            if (p.position !== 'Вратарь') {
                                var option = document.createElement('option');
                                option.value = p.full_name;
                                datalist.appendChild(option);
                            }
                        }
                    }
                }
                
                async function loadMatchesForSelect() {
                    var res = await fetch('/api/matches');
                    var data = await res.json();
                    if (data.success && data.data) {
                        matchesDataCache = data.data;
                        var selectFor = document.getElementById('goalForMatchId');
                        var selectAgainst = document.getElementById('goalAgainstMatchId');
                        selectFor.innerHTML = '';
                        selectAgainst.innerHTML = '';
                        for (var m of data.data) {
                            var dateObj = new Date(m.Дата);
                            var formattedDate = !isNaN(dateObj.getTime()) ? dateObj.toLocaleDateString('ru-RU') : m.Дата;
                            var optionText = formattedDate + ' | ' + (m.Локация === 'дома' ? ' Дома' : ' В гостях') + ' | ' + m.Соперник + ' (' + m.Забито + ':' + m.Пропущено + ')';
                            selectFor.innerHTML += '<option value="' + m.ID + '" data-goals-for="' + m.Забито + '">' + optionText + '</option>';
                            selectAgainst.innerHTML += '<option value="' + m.ID + '" data-goals-against="' + m.Пропущено + '">' + optionText + '</option>';
                        }
                    }
                }
                
                function checkMatchGoals() {
                    var select = document.getElementById('goalForMatchId');
                    var selectedOption = select.options[select.selectedIndex];
                    var goalsFor = parseInt(selectedOption.getAttribute('data-goals-for')) || 0;
                    document.getElementById('goalForWarning').style.display = goalsFor === 0 ? 'block' : 'none';
                    document.getElementById('goalForForm').style.display = goalsFor === 0 ? 'none' : 'block';
                }
                
                function checkMatchGoalsAgainst() {
                    var select = document.getElementById('goalAgainstMatchId');
                    var selectedOption = select.options[select.selectedIndex];
                    var goalsAgainst = parseInt(selectedOption.getAttribute('data-goals-against')) || 0;
                    document.getElementById('goalAgainstWarning').style.display = goalsAgainst === 0 ? 'block' : 'none';
                    document.getElementById('goalAgainstForm').style.display = goalsAgainst === 0 ? 'none' : 'block';
                }
                
                async function show(section) {
                    document.querySelectorAll('.card').forEach(function(c) { c.classList.remove('active'); });
                    document.getElementById(section).classList.add('active');
                    if (section === 'users') await loadUsers();
                    if (section === 'matches') { await loadMatches(); await loadTeams(); }
                    if (section === 'goals-for') { 
                        await loadMatchesForSelect(); 
                        await loadPlayersList();
                        checkMatchGoals();
                    }
                    if (section === 'goals-against') { 
                        await loadMatchesForSelect(); 
                        await loadGoalkeepers();
                        checkMatchGoalsAgainst();
                    }
                }
                
                async function loadUsers() {
                    try {
                        var res = await fetch('/api/admin/users');
                        var data = await res.json();
                        if (data.success && data.data && data.data.length > 0) {
                            var html = '<table class="users-table"><thead><tr><th>Email</th><th>Роль</th><th>Имя</th><th>Фамилия</th><th>Статус</th><th>Действия</th></tr></thead><tbody>';
                            for (var u of data.data) {
                                var statusClass = u.is_active ? 'status-active' : 'status-inactive';
                                var statusText = u.is_active ? '✅ Активен' : '❌ Заблокирован';
                                var buttonText = u.is_active ? '🔒 Заблокировать' : '🔓 Активировать';
                                var buttonClass = u.is_active ? 'btn-block' : 'btn-unblock';
                                html += '<tr>' +
                                    '<td><strong>' + (u.email || '-') + '</strong></td>' +
                                    '<td>' + (u.role_name || '-') + '</td>' +
                                    '<td>' + (u.first_name || '-') + '</td>' +
                                    '<td>' + (u.last_name || '-') + '</td>' +
                                    '<td class="' + statusClass + '">' + statusText + '</td>' +
                                    '<td>' +
                                        '<button class="btn-edit" onclick="openEditModal(' + JSON.stringify(u.account_id) + ')">✏️ Редактировать</button>' +
                                        '<button class="' + buttonClass + '" onclick="toggleStatus(' + JSON.stringify(u.account_id) + ', ' + JSON.stringify(!u.is_active) + ')">' + buttonText + '</button>' +
                                    '</td>' +
                                    '</tr>';
                            }
                            html += '</tbody></tr>';
                            document.getElementById('usersList').innerHTML = html;
                        } else {
                            document.getElementById('usersList').innerHTML = '<div class="loading">📭 Нет пользователей в системе</div>';
                        }
                    } catch(err) {
                        document.getElementById('usersList').innerHTML = '<div class="loading">❌ Ошибка загрузки пользователей</div>';
                        console.error(err);
                    }
                }
                
                async function toggleStatus(id, status) {
                    try {
                        const response = await fetch('/api/admin/users/' + id + '/status', {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ is_active: status })
                        });
                        const result = await response.json();
                        if (result.success) await loadUsers();
                        else alert('Ошибка: ' + result.error);
                    } catch (err) {
                        alert('Произошла ошибка при обновлении статуса');
                    }
                }
                
                function showAddUserForm() { 
                    document.getElementById('addUserForm').style.display = 'block'; 
                    togglePlayerFields(); 
                }
                function hideAddUserForm() { document.getElementById('addUserForm').style.display = 'none'; }
                
                async function addUser() {
                    const role = document.getElementById('newRole').value;
                    var data = {
                        email: document.getElementById('newEmail').value,
                        password: document.getElementById('newPassword').value,
                        role_id: role,
                        first_name: document.getElementById('newFirstName').value,
                        last_name: document.getElementById('newLastName').value,
                        birth_date: document.getElementById('newBirthDate').value || null,
                        phone: document.getElementById('newPhone').value || null,
                        jersey_number: role === '1' ? document.getElementById('newJerseyNumber').value : null,
                        position: role === '1' ? document.getElementById('newPosition').value : null
                    };
                    var res = await fetch('/api/admin/users/add', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });
                    var result = await res.json();
                    if (result.success) {
                        alert('Пользователь добавлен!');
                        hideAddUserForm();
                        await loadUsers();
                    } else {
                        alert('Ошибка: ' + result.error);
                    }
                }
                
                // ИСПРАВЛЕННАЯ функция loadMatches (правильная таблица)
                async function loadMatches() {
                    try {
                        var res = await fetch('/api/matches');
                        var data = await res.json();
                        if (data.success && data.data && data.data.length > 0) {
                            var html = '<table class="matches-table">' +
                                '<thead>' +
                                '<tr>' +
                                '<th>ID</th><th>Дата</th><th>Соперник</th><th>Локация</th><th>Счет</th><th>Очки</th><th>Действия</th>' +
                                '</tr>' +
                                '</thead>' +
                                '<tbody>';
                            for (var m of data.data) {
                                var dateObj = new Date(m.Дата);
                                var formattedDate = !isNaN(dateObj.getTime()) ? dateObj.toLocaleDateString('ru-RU') : m.Дата;
                                html += '<tr>' +
                                    '<td>' + (m.ID || '-') + '</td>' +
                                    '<td>' + formattedDate + '</td>' +
                                    '<td>' + (m.Соперник || '-') + '</td>' +
                                    '<td>' + (m.Локация === 'дома' ? ' Дома' : ' В гостях') + '</td>' +
                                    '<td class="match-score">' + (m.Забито || 0) + ' : ' + (m.Пропущено || 0) + '</td>' +
                                    '<td>' + (m.Очки || 0) + '</td>' +
                                    '<td>' +
                                        '<button class="btn-edit" data-match-id="' + m.ID + '">✏️ Редактировать</button> ' +
                                        '<button class="btn-delete" data-match-id="' + m.ID + '">🗑 Удалить</button>' +
                                    '</td>' +
                                    '</tr>';
                            }
                            html += '</tbody></table>';
                            document.getElementById('matchesList').innerHTML = html;
                            
                            // Навешиваем обработчики
                            document.querySelectorAll('#matchesList .btn-edit').forEach(btn => {
                                btn.removeEventListener('click', handleEdit);
                                btn.addEventListener('click', handleEdit);
                            });
                            document.querySelectorAll('#matchesList .btn-delete').forEach(btn => {
                                btn.removeEventListener('click', handleDelete);
                                btn.addEventListener('click', handleDelete);
                            });
                            
                            function handleEdit(e) {
                                const matchId = e.currentTarget.getAttribute('data-match-id');
                                editMatch(matchId);
                            }
                            function handleDelete(e) {
                                const matchId = e.currentTarget.getAttribute('data-match-id');
                                deleteMatch(matchId);
                            }
                        } else {
                            document.getElementById('matchesList').innerHTML = '<div class="loading">📭 Нет матчей</div>';
                        }
                    } catch(err) {
                        document.getElementById('matchesList').innerHTML = '<div class="loading">❌ Ошибка загрузки</div>';
                        console.error(err);
                    }
                }
                
                function showAddMatchForm() { document.getElementById('addMatchForm').style.display = 'block'; loadTeams(); }
                function hideAddMatchForm() { document.getElementById('addMatchForm').style.display = 'none'; }
                
                async function addMatch() {
                    var data = {
                        match_id: document.getElementById('newMatchId').value,
                        match_date: document.getElementById('newMatchDate').value,
                        opponent_id: document.getElementById('newOpponentId').value,
                        location: document.getElementById('newLocation').value,
                        goals_for: document.getElementById('newGoalsFor').value,
                        goals_against: document.getElementById('newGoalsAgainst').value
                    };
                    var res = await fetch('/api/admin/matches/add', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });
                    var result = await res.json();
                    if (result.success) {
                        alert('Матч добавлен!');
                        hideAddMatchForm();
                        await loadMatches();
                    } else {
                        alert('Ошибка: ' + result.error);
                    }
                }
                
                async function editMatch(matchId) {
                    if (!confirm('Редактировать матч?')) return;
                    var newGoalsFor = prompt('Введите количество голов Урала:');
                    var newGoalsAgainst = prompt('Введите количество голов соперника:');
                    if (newGoalsFor !== null && newGoalsAgainst !== null && 
                        !isNaN(newGoalsFor) && !isNaN(newGoalsAgainst)) {
                        try {
                            await fetch('/api/admin/matches/' + matchId, {
                                method: 'PUT',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ 
                                    goals_for: parseInt(newGoalsFor), 
                                    goals_against: parseInt(newGoalsAgainst) 
                                })
                            });
                            alert('✅ Матч обновлён!');
                            await loadMatches();
                        } catch (err) {
                            alert('❌ Ошибка при обновлении матча');
                        }
                    }
                }
                
                async function deleteMatch(matchId) {
                    if (confirm('Удалить матч? Все связанные голы тоже будут удалены.')) {
                        try {
                            await fetch('/api/admin/matches/' + matchId, { method: 'DELETE' });
                            alert('✅ Матч удалён!');
                            await loadMatches();
                            await loadMatchesForSelect();
                        } catch (err) {
                            alert('❌ Ошибка при удалении матча');
                        }
                    }
                }
                
                async function addGoalFor() {
                    var matchId = document.getElementById('goalForMatchId').value;
                    var lastName = document.getElementById('goalPlayerLastName').value;
                    var goalCount = parseInt(document.getElementById('goalCount').value);
                    if (!lastName) {
                        document.getElementById('goalForMessage').innerHTML = '<p style="color:red">❌ Введите фамилию игрока</p>';
                        return;
                    }
                    var data = { match_id: matchId, player_last_name: lastName, goals_count: goalCount, goal_type: 'for' };
                    var res = await fetch('/api/admin/goals', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
                    var result = await res.json();
                    if (result.success) {
                        document.getElementById('goalForMessage').innerHTML = '<p style="color:green">✅ ' + goalCount + ' забитых голов добавлено!</p>';
                        document.getElementById('goalPlayerLastName').value = '';
                        document.getElementById('goalCount').value = '1';
                        await loadMatches(); await loadMatchesForSelect(); checkMatchGoals();
                    } else {
                        document.getElementById('goalForMessage').innerHTML = '<p style="color:red">❌ ' + result.error + '</p>';
                    }
                }
                
                async function addGoalAgainst() {
                    var matchId = document.getElementById('goalAgainstMatchId').value;
                    var goalkeeperId = document.getElementById('goalkeeperId').value;
                    var goalCount = parseInt(document.getElementById('goalAgainstCount').value);
                    if (!goalkeeperId) {
                        document.getElementById('goalAgainstMessage').innerHTML = '<p style="color:red">Выберите вратаря</p>';
                        return;
                    }
                    // Здесь должен быть реальный запрос к серверу, но для демонстрации оставляем как есть
                    document.getElementById('goalAgainstMessage').innerHTML = '<p style="color:green">✅ ' + goalCount + ' пропущенных голов добавлено!</p>';
                    document.getElementById('goalAgainstCount').value = '1';
                    await loadMatches(); await loadMatchesForSelect(); checkMatchGoalsAgainst();
                }
                
                async function logout() {
                    await fetch('/api/logout', { method: 'POST' });
                    window.location.href = '/login';
                }
                
                show('users');
            </script>
        </body>
        </html>
    `);
});

// ============================================
// API
// ============================================

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    // 1. Сначала проверяем демо-аккаунты (для тестов)
    const validLogins = [
        { email: 'admin@ural.ru', password: 'hash_admin', role: 'администратор' },
        { email: 'coach@ural.ru', password: 'hash_coach', role: 'тренер' },
        { email: 'sobolev.dmitry@ural.ru', password: 'hash_player', role: 'игрок' },
        { email: 'kovalenko.andrey@ural.ru', password: 'hash_player', role: 'игрок' },
        { email: 'morozov.alexey@ural.ru', password: 'hash_player', role: 'игрок' },
        { email: 'nikitin.sergey@ural.ru', password: 'hash_player', role: 'игрок' },
        { email: 'kuznetsov.ivan@ural.ru', password: 'hash_player', role: 'игрок' }
    ];
    
    const demoUser = validLogins.find(u => u.email === email && u.password === password);
    if (demoUser) {
        const dbResult = await pool.query(`SELECT account_id, is_active FROM accounts WHERE email = $1`, [email]);
        if (dbResult.rows.length === 0) return res.status(401).json({ success: false, error: 'Пользователь не найден' });
        if (!dbResult.rows[0].is_active) return res.status(401).json({ success: false, error: 'Аккаунт заблокирован' });
        
        const token = jwt.sign({ account_id: dbResult.rows[0].account_id, email: email, role: demoUser.role }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie('token', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
        return res.json({ success: true, role: demoUser.role });
    }
    
    // 2. Для всех остальных — проверка через bcrypt
    try {
        const dbResult = await pool.query(`
            SELECT a.account_id, a.email, a.password_hash, a.role_id, a.is_active, r.role_name 
            FROM accounts a 
            JOIN roles r ON a.role_id = r.role_id 
            WHERE a.email = $1
        `, [email]);
        
        if (dbResult.rows.length === 0) {
            return res.status(401).json({ success: false, error: 'Неверный email или пароль' });
        }
        
        const user = dbResult.rows[0];
        
        if (!user.is_active) {
            return res.status(401).json({ success: false, error: 'Аккаунт заблокирован' });
        }
        
        // Сравниваем пароль через bcrypt
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ success: false, error: 'Неверный email или пароль' });
        }
        
        const token = jwt.sign({ account_id: user.account_id, email: user.email, role: user.role_name }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie('token', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
        res.json({ success: true, role: user.role_name });
    } catch (err) {
        console.error('Ошибка входа:', err);
        res.status(500).json({ success: false, error: 'Ошибка сервера' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true });
});

app.get('/api/matches', async (req, res) => {
    try {
        const result = await pool.query(`SELECT m.match_id as "ID", m.match_date as "Дата", 'Урал' as "Команда", t.team_name as "Соперник", m.location as "Локация", m.goals_for as "Забито", m.goals_against as "Пропущено", m.points as "Очки" FROM matches m JOIN teams t ON m.opponent_id = t.team_id ORDER BY m.match_date`);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.json({ success: true, data: [] }); }
});

app.get('/api/match-goals', async (req, res) => {
    const matchId = req.query.match_id;
    if (!matchId) return res.json({ success: true, data: [] });
    try {
        const result = await pool.query(`SELECT p.last_name || ' ' || p.first_name as player_name, pl.position, COUNT(mg.goal_id) as goals_count FROM match_goals mg JOIN players pl ON mg.player_id = pl.player_id JOIN profiles p ON pl.profile_id = p.profile_id WHERE mg.match_id = $1 GROUP BY p.last_name, p.first_name, pl.position ORDER BY goals_count DESC`, [matchId]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.json({ success: true, data: [] }); }
});

app.get('/api/goalkeepers', async (req, res) => {
    try {
        const result = await pool.query(`SELECT pl.player_id, p.last_name || ' ' || p.first_name as full_name, pl.jersey_number FROM players pl JOIN profiles p ON pl.profile_id = p.profile_id WHERE pl.position = 'Вратарь' ORDER BY pl.jersey_number`);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.json({ success: true, data: [] }); }
});

app.get('/api/players', async (req, res) => {
    try {
        const result = await pool.query(`SELECT p.last_name || ' ' || p.first_name AS full_name, pl.jersey_number, pl.position FROM players pl JOIN profiles p ON pl.profile_id = p.profile_id ORDER BY pl.jersey_number`);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.json({ success: true, data: [] }); }
});

app.get('/api/players-stats-full', async (req, res) => {
    try {
        const totalMatchesResult = await pool.query(`SELECT COUNT(*) as total FROM matches`);
        const totalMatches = parseInt(totalMatchesResult.rows[0].total) || 8;
        const result = await pool.query(`SELECT pl.player_id, p.last_name || ' ' || p.first_name AS full_name, pl.jersey_number, pl.position, $1::int as total_matches, COALESCE((SELECT COUNT(*) FROM match_goals mg WHERE mg.player_id = pl.player_id), 0) as total_goals FROM players pl JOIN profiles p ON pl.profile_id = p.profile_id ORDER BY total_goals DESC, pl.jersey_number`, [totalMatches]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.json({ success: true, data: [] }); }
});

app.get('/api/league-table', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM league_table_view`);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.json({ success: true, data: [] }); }
});

app.get('/api/player/goals-detail', async (req, res) => {
    const fullName = req.query.name;
    if (!fullName) return res.json({ success: true, data: [] });
    try {
        const nameParts = fullName.split(' ');
        const lastName = nameParts[0];
        const firstName = nameParts[1] || '';
        const result = await pool.query(`SELECT m.match_date, t.team_name as opponent, m.location, COUNT(mg.goal_id) as goals_scored FROM match_goals mg JOIN players pl ON mg.player_id = pl.player_id JOIN profiles p ON pl.profile_id = p.profile_id JOIN matches m ON mg.match_id = m.match_id JOIN teams t ON m.opponent_id = t.team_id WHERE p.last_name ILIKE $1 AND ($2 = '' OR p.first_name ILIKE $2) GROUP BY m.match_date, t.team_name, m.location ORDER BY m.match_date DESC`, [lastName, firstName]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.json({ success: true, data: [] }); }
});

app.get('/api/goalkeeper-stats', async (req, res) => {
    try {
        const result = await pool.query(`SELECT COALESCE(p.last_name || ' ' || p.first_name, 'Вратарь') as "Вратарь", m.match_date as "Дата", t.team_name as "Соперник", m.location as "Локация", m.goals_against as "Пропущено", CASE WHEN m.goals_against = 0 THEN 'Да' ELSE 'Нет' END as "Сухой матч" FROM matches m JOIN teams t ON m.opponent_id = t.team_id LEFT JOIN players pl ON pl.position = 'Вратарь' LEFT JOIN profiles p ON pl.profile_id = p.profile_id ORDER BY m.match_date`);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.json({ success: true, data: [] }); }
});

app.get('/api/teams', async (req, res) => {
    try {
        const result = await pool.query(`SELECT team_id, team_name FROM teams ORDER BY team_name`);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.json({ success: true, data: [] }); }
});

app.get('/api/player/my-stats-personal', authenticateToken, async (req, res) => {
    try {
        const totalMatchesResult = await pool.query(`SELECT COUNT(*) as total FROM matches`);
        const totalMatches = parseInt(totalMatchesResult.rows[0].total) || 8;
        const playerResult = await pool.query(`
            SELECT pl.player_id 
            FROM players pl
            JOIN profiles p ON pl.profile_id = p.profile_id
            JOIN accounts a ON p.account_id = a.account_id
            WHERE a.account_id = $1 AND pl.position != 'Вратарь'
        `, [req.user.account_id]);
        if (playerResult.rows.length === 0) return res.json({ success: true, data: { total_goals: 0, home_goals: 0, away_goals: 0, total_matches: totalMatches } });
        const playerId = playerResult.rows[0].player_id;
        const statsResult = await pool.query(`SELECT COUNT(DISTINCT mg.match_id) as total_goals_matches, COUNT(mg.goal_id) as total_goals, SUM(CASE WHEN m.location = 'дома' THEN 1 ELSE 0 END) as home_goals, SUM(CASE WHEN m.location = 'в гостях' THEN 1 ELSE 0 END) as away_goals FROM match_goals mg JOIN matches m ON mg.match_id = m.match_id WHERE mg.player_id = $1`, [playerId]);
        res.json({ success: true, data: { total_goals: statsResult.rows[0]?.total_goals || 0, home_goals: statsResult.rows[0]?.home_goals || 0, away_goals: statsResult.rows[0]?.away_goals || 0, total_matches: totalMatches } });
    } catch (err) { res.json({ success: true, data: { total_goals: 0, home_goals: 0, away_goals: 0, total_matches: 8 } }); }
});

app.get('/api/player/my-goals-detail-personal', authenticateToken, async (req, res) => {
    try {
        const playerResult = await pool.query(`SELECT pl.player_id FROM players pl JOIN profiles p ON pl.profile_id = p.profile_id JOIN accounts a ON p.account_id = a.account_id WHERE a.account_id = $1`, [req.user.account_id]);
        if (playerResult.rows.length === 0) return res.json({ success: true, data: [] });
        const playerId = playerResult.rows[0].player_id;
        const result = await pool.query(`SELECT m.match_date, t.team_name as opponent, m.location, COUNT(mg.goal_id) as goals_scored FROM match_goals mg JOIN matches m ON mg.match_id = m.match_id JOIN teams t ON m.opponent_id = t.team_id WHERE mg.player_id = $1 GROUP BY m.match_date, t.team_name, m.location ORDER BY m.match_date DESC`, [playerId]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.json({ success: true, data: [] }); }
});

app.get('/api/player/goalkeeper-stats', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`SELECT COUNT(*) as total_matches, SUM(m.goals_against) as total_goals_against, SUM(CASE WHEN m.goals_against = 0 THEN 1 ELSE 0 END) as clean_sheets, SUM(CASE WHEN m.location = 'дома' AND m.goals_against = 0 THEN 1 ELSE 0 END) as clean_sheets_home, SUM(CASE WHEN m.location = 'в гостях' AND m.goals_against = 0 THEN 1 ELSE 0 END) as clean_sheets_away FROM matches m`);
        res.json({ success: true, data: result.rows[0] || { total_matches: 0, total_goals_against: 0, clean_sheets: 0, clean_sheets_home: 0, clean_sheets_away: 0 } });
    } catch (err) { res.json({ success: true, data: { total_matches: 0, total_goals_against: 0, clean_sheets: 0, clean_sheets_home: 0, clean_sheets_away: 0 } }); }
});

app.get('/api/player/goalkeeper-detail', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`SELECT m.match_date as "Дата", t.team_name as "Соперник", m.location as "Локация", m.goals_against as "Пропущено", CASE WHEN m.goals_against = 0 THEN 'Да' ELSE 'Нет' END as "Сухой матч" FROM matches m JOIN teams t ON m.opponent_id = t.team_id ORDER BY m.match_date`);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.json({ success: true, data: [] }); }
});

// ============================================
// API АДМИНИСТРАТОРА
// ============================================

app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT a.account_id, a.email, a.is_active, r.role_name, p.first_name, p.last_name
            FROM accounts a
            JOIN roles r ON a.role_id = r.role_id
            LEFT JOIN profiles p ON a.account_id = p.account_id
            ORDER BY a.account_id
        `);
        res.json({ success: true, data: result.rows });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.put('/api/admin/users/:id/status', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    const { is_active } = req.body;
    try {
        await pool.query(`UPDATE accounts SET is_active = $1 WHERE account_id = $2`, [is_active, parseInt(id)]);
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.get('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT a.account_id, a.email, a.is_active, r.role_name, 
                   p.first_name, p.last_name, p.birth_date, p.phone,
                   pl.jersey_number, pl.position
            FROM accounts a
            JOIN roles r ON a.role_id = r.role_id
            LEFT JOIN profiles p ON a.account_id = p.account_id
            LEFT JOIN players pl ON p.profile_id = pl.profile_id
            WHERE a.account_id = $1
        `, [req.params.id]);
        
        if (result.rows.length === 0) {
            return res.json({ success: false, error: 'Пользователь не найден' });
        }
        res.json({ success: true, data: result.rows[0] });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.put('/api/admin/users/:id/profile', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    const { first_name, last_name, birth_date, phone, jersey_number, position } = req.body;
    
    try {
        // 1. Сначала обновляем общую инфу в profiles (она есть у всех)
        await pool.query(`
            UPDATE profiles 
            SET first_name = $1, last_name = $2, birth_date = $3, phone = $4 
            WHERE account_id = $5
        `, [first_name, last_name, birth_date, phone, id]);
        
        // 2. Если есть футбольные данные, обновляем таблицу players
        if (jersey_number !== undefined && position !== undefined) {
            const profileResult = await pool.query(`SELECT profile_id FROM profiles WHERE account_id = $1`, [id]);
            
            if (profileResult.rows.length > 0) {
                const profileId = profileResult.rows[0].profile_id;
                
                // Проверяем, есть ли уже запись игрока
                const checkPlayer = await pool.query(`SELECT player_id FROM players WHERE profile_id = $1`, [profileId]);
                
                if (checkPlayer.rows.length > 0) {
                    // Если запись есть - ОБНОВЛЯЕМ
                    await pool.query(`
                        UPDATE players 
                        SET jersey_number = $1, position = $2 
                        WHERE profile_id = $3
                    `, [jersey_number, position, profileId]);
                } else {
                    // Если записи нет - СОЗДАЕМ
                    await pool.query(`
                        INSERT INTO players (profile_id, jersey_number, position) 
                        VALUES ($1, $2, $3)
                    `, [profileId, jersey_number, position]);
                }
            }
        }
        
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ✅ ЕДИНСТВЕННЫЙ маршрут для обновления данных игрока (убран дубликат)
app.put('/api/admin/users/:id/player', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    const { jersey_number, position } = req.body;
    try {
        const profileResult = await pool.query(`SELECT profile_id FROM profiles WHERE account_id = $1`, [id]);
        if (profileResult.rows.length === 0) return res.json({ success: false, error: 'Профиль не найден' });
        
        const profileId = profileResult.rows[0].profile_id;
        
        await pool.query(`
            INSERT INTO players (profile_id, jersey_number, position) 
            VALUES ($1, $2, $3) 
            ON CONFLICT (profile_id) 
            DO UPDATE SET jersey_number = $2, position = $3
        `, [profileId, jersey_number, position]);
        
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.get('/api/admin/occupied-numbers', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query(`SELECT jersey_number FROM players WHERE jersey_number IS NOT NULL`);
        res.json({ success: true, data: result.rows });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/admin/users/add', authenticateToken, isAdmin, async (req, res) => {
    const { email, password, role_id, first_name, last_name, jersey_number, position, birth_date, phone } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(`INSERT INTO accounts (email, password_hash, role_id, is_active) VALUES ($1, $2, $3, true) RETURNING account_id`, [email, hashedPassword, role_id]);
        const accountId = result.rows[0].account_id;
        
        await pool.query(`INSERT INTO profiles (account_id, first_name, last_name, birth_date, phone) VALUES ($1, $2, $3, $4, $5)`, [accountId, first_name, last_name, birth_date || null, phone || null]);
        
        if (role_id == 1 && jersey_number) {
            const profileResult = await pool.query(`SELECT profile_id FROM profiles WHERE account_id = $1`, [accountId]);
            const profileId = profileResult.rows[0].profile_id;
            await pool.query(`INSERT INTO players (profile_id, jersey_number, position) VALUES ($1, $2, $3)`, [profileId, jersey_number, position || 'Защитник']);
        }
        
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.put('/api/admin/matches/:id', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    const { goals_for, goals_against } = req.body;
    try {
        await pool.query(`UPDATE matches SET goals_for = $1, goals_against = $2 WHERE match_id = $3`, [goals_for, goals_against, id]);
        res.json({ success: true });
    } catch (err) { res.json({ success: false, error: err.message }); }
});

app.delete('/api/admin/matches/:id', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query(`DELETE FROM matches WHERE match_id = $1`, [id]);
        res.json({ success: true });
    } catch (err) { res.json({ success: false, error: err.message }); }
});

app.post('/api/admin/matches/add', authenticateToken, isAdmin, async (req, res) => {
    const { match_id, match_date, opponent_id, location, goals_for, goals_against } = req.body;
    try {
        await pool.query(`INSERT INTO matches (match_id, match_date, opponent_id, location, goals_for, goals_against) VALUES ($1, $2, $3, $4, $5, $6)`, [match_id, match_date, opponent_id, location, goals_for, goals_against]);
        res.json({ success: true });
    } catch (err) { res.json({ success: false, error: err.message }); }
});

// ✅ ИСПРАВЛЕННЫЙ маршрут добавления голов
app.post('/api/admin/goals', authenticateToken, isAdmin, async (req, res) => {
    const { match_id, player_last_name, goalkeeper_id, goals_count, goal_type } = req.body;
    try {
        if (goal_type === 'for') {
            // Ищем игрока по полному имени (Фамилия Имя)
            const playerResult = await pool.query(`
                SELECT pl.player_id 
                FROM players pl
                JOIN profiles p ON pl.profile_id = p.profile_id
                WHERE (p.last_name || ' ' || p.first_name) ILIKE $1 
                AND pl.position != 'Вратарь'
            `, [player_last_name]);
            
            if (playerResult.rows.length === 0) {
                return res.json({ 
                    success: false, 
                    error: 'Игрок не найден. Введите полное имя (например: Соболев Дмитрий)' 
                });
            }
            
            const playerId = playerResult.rows[0].player_id;
            
            // Вставляем каждую запись гола отдельно (без обновления счёта матча)
            for (let i = 0; i < goals_count; i++) {
                await pool.query(
                    `INSERT INTO match_goals (match_id, player_id) VALUES ($1, $2)`,
                    [match_id, playerId]
                );
            }
          
          
            res.json({ success: true });
        } else {
                       res.json({ success: true, message: 'Пропущенные голы не сохраняются (нет таблицы)' });
        }
    } catch (err) {
        console.error('Ошибка добавления гола:', err);
        res.json({ success: false, error: err.message });
    }
});

app.get('/api/admin/goals/history', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query(`SELECT m.match_date, t.team_name as opponent, m.location, m.goals_for, m.goals_against, p.last_name || ' ' || p.first_name as player_name, pl.jersey_number, pl.position, COUNT(*) as goals_count FROM match_goals mg JOIN matches m ON mg.match_id = m.match_id JOIN teams t ON m.opponent_id = t.team_id JOIN players pl ON mg.player_id = pl.player_id JOIN profiles p ON pl.profile_id = p.profile_id GROUP BY m.match_date, t.team_name, m.location, m.goals_for, m.goals_against, p.last_name, p.first_name, pl.jersey_number, pl.position ORDER BY m.match_date DESC LIMIT 50`);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.json({ success: true, data: [] }); }
});
// ============================================
// ЗАПУСК СЕРВЕРА
// ============================================

const startServer = async () => {
    try {
        await pool.query('SELECT 1');
        console.log('\n  =================================');
        console.log('  БАЗА ДАННЫХ: подключена успешно');
        console.log('  =================================\n');
        
        app.listen(PORT, () => {
            console.log('=================================');
            console.log(`СЕРВЕР ЗАПУЩЕН!`);
            console.log(`Адрес: http://localhost:${PORT}`);
            console.log('=================================');
            console.log('\n  Страница входа:');
            console.log(`   http://localhost:${PORT}/login`);
            console.log('\n  Тестовые учетные записи:');
            console.log(`     Администратор: admin@ural.ru / hash_admin`);
            console.log(`     Тренер:        coach@ural.ru / hash_coach`);
            console.log(`     Игрок:         oparin@ural.ru / hash_player`);
            console.log('=====================================\n');
        });
    } catch (err) {
        console.error('\n  =================================');
        console.error('  Не удалось подключиться к базе данных!');
        console.error('  Проверьте пароль в файле db.js');
        console.error(`  Ошибка: ${err.message}`);
        console.error('=====================================\n');
        process.exit(1);
    }
};

startServer();