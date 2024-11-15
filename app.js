const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const fs = require('fs');
const { exec } = require('child_process');
require('dotenv').config();

const app = express();
const PORT = 3000;

app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 }
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: false }));

app.get('/', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
        req.session.isAuthenticated = true;
        res.redirect('/dashboard');
    } else {
        res.send('Неверные учетные данные!');
    }
});

function checkAuth(req, res, next) {
    if (req.session.isAuthenticated) {
        return next();
    }
    res.redirect('/');
}

app.get('/dashboard', checkAuth, (req, res) => {
    const certsPath = '/etc/openvpn/easy-rsa/pki/issued';
    const serverAccount = 'server';

    fs.readdir(certsPath, (err, files) => {
        if (err) {
            console.error("Ошибка при чтении папки сертификатов:", err);
            return res.send("Не удалось загрузить список пользователей.");
        }

        const users = files
            .filter(file => file.endsWith('.crt') && !file.startsWith(serverAccount))
            .map(file => file.replace('.crt', ''));

        console.log("Найденные пользователи:", users);
        res.render('dashboard', { users });
    });
});

app.post('/delete-user', checkAuth, (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.send('Имя пользователя не указано.');
    }

    console.log(`Попытка удаления клиента: ${username}`);

    const revokeCommands = `
    cd /etc/openvpn/easy-rsa &&
    ./easyrsa --batch revoke "${username}" &&
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl &&
    rm -f /etc/openvpn/crl.pem &&
    cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem &&
    chmod 644 /etc/openvpn/crl.pem &&
    find ${process.env.VPN_CONFIG_PATH} -name "${username}.ovpn" -delete &&
    sed -i "/CN=${username}/d" /etc/openvpn/easy-rsa/pki/index.txt &&
    systemctl restart openvpn@server
    `;

    exec(revokeCommands, (error, stdout, stderr) => {
        if (error) {
            console.error(`Ошибка при удалении клиента ${username}:`, error);
            return res.send(`Ошибка: ${error.message}`);
        }
        if (stderr) {
            console.error(`Стандартный поток ошибок при удалении клиента ${username}:`, stderr);
        }

        console.log(`Клиент ${username} успешно удалён:\n${stdout}`);
        res.redirect('/dashboard');
    });
});

// Маршрут для добавления нового клиента
app.post('/add-user', (req, res) => {
    const { username, usePassword } = req.body;

    // Проверка имени пользователя
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
        return res.status(400).send('Некорректное имя пользователя. Допустимы только буквенно-цифровые символы, подчеркивания и дефисы.');
    }

// Проверка на существование пользователя
exec(`bash -c "
    CLIENTEXISTS=\$(grep -c -E '/CN=${username}' /etc/openvpn/easy-rsa/pki/index.txt)
    if [[ \\$CLIENTEXISTS -gt 0 ]]; then
        echo 'EXISTS'
    else
        echo 'AVAILABLE'
    fi
"`, (err, stdout, stderr) => {
    if (err) {
        console.error(`Ошибка при выполнении проверки пользователя: ${stderr}`);
        return res.status(500).send('Ошибка при проверке существования клиента');
    }

    const result = stdout.trim();
    if (result === 'EXISTS') {
        return res.status(400).send('Пользователь с таким именем уже существует. Пожалуйста, выберите другое имя.');
    }

    if (result === 'AVAILABLE') {
        console.log('Имя доступно, продолжаем создание пользователя...');

    }

        // Команда для создания клиента (по умолчанию без пароля)
        const command = `
            cd /etc/openvpn/easy-rsa &&
            EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "${username}" ${usePassword ? '' : 'nopass'} &&
            cp /etc/openvpn/client-template.txt ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
            echo "<ca>" >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
            cat /etc/openvpn/easy-rsa/pki/ca.crt >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
            echo "</ca>" >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
            echo "<cert>" >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
            awk '/BEGIN/,/END CERTIFICATE/' /etc/openvpn/easy-rsa/pki/issued/${username}.crt >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
            echo "</cert>" >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
            echo "<key>" >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
            cat /etc/openvpn/easy-rsa/pki/private/${username}.key >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
            echo "</key>" >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
            if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
                echo "<tls-crypt>" >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
                cat /etc/openvpn/tls-crypt.key >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
                echo "</tls-crypt>" >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn;
            elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
                echo "key-direction 1" >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
                echo "<tls-auth>" >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
                cat /etc/openvpn/tls-auth.key >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn &&
                echo "</tls-auth>" >> ${process.env.VPN_CONFIG_PATH}/${username}.ovpn;
            fi
        `;

        exec(command, (error, stdout, stderr) => {
            if (error) {
                return res.status(500).send(`Ошибка при создании клиента: ${stderr}`);
            }
//            res.send(`Пользователь ${username} добавлен. Файл конфигурации создан в ${process.env.VPN_CONFIG_PATH}/${username}.ovpn`);
            res.redirect('/dashboard');
        });
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.send('Ошибка при выходе');
        }
        res.redirect('/');
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
