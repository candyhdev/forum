const canvas = document.getElementById('matrix');
const ctx = canvas.getContext('2d');

// Устанавливаем размеры холста по размеру окна
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

// Бинарные символы
const binaryChars = '01';

// Задаём размеры колонок (по символам)
const fontSize = 16;
const columns = canvas.width / fontSize;

// Массив для отслеживания "падения" символов для каждой колонки
const drops = Array(Math.floor(columns)).fill(1);

// Функция для случайного выбора бинарного символа
function getRandomBinaryChar() {
    return binaryChars[Math.floor(Math.random() * binaryChars.length)];
}

// Функция для рисования падающего кода
function draw() {
    // Прозрачность для эффекта следа
    ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Устанавливаем цвет и шрифт символов
    ctx.fillStyle = 'rgba(210,0,0,0.62)'; // Зелёный цвет
    ctx.font = `${fontSize}px Courier New`;

    // Проходим по каждому символу в каждом столбце
    for (let i = 0; i < drops.length; i++) {
        // Выбираем случайный бинарный символ
        const text = getRandomBinaryChar();

        // Рисуем символ в позиции (i * fontSize, drop[i] * fontSize)
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        // Если символы ушли за нижнюю границу или случайным образом, начинаем падение с верха
        if (drops[i] * fontSize > canvas.height || Math.random() > 0.95) {
            drops[i] = 0;
        }

        // Падаем вниз
        drops[i]++;
    }
}

// Обработчик клика по слову "away"
document.getElementById('clickable-word').addEventListener('click', function() {
    window.location.href = 'away'; // Переход на страницу
});


// Запуск анимации
setInterval(draw, 50);
