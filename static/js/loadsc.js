window.addEventListener('load', () => {
    const loadingScreen = document.getElementById('loading-screen');
    const loadingImage = document.querySelector('.loading-image');

    // Устанавливаем фиксированные размеры через JS, если они не применились
    loadingImage.style.width = '80px';
    loadingImage.style.height = '80px';

    // Проверяем, загружено ли изображение
    if (loadingImage.complete) {
        loadingImage.style.visibility = 'visible'; // Если уже загружено, делаем видимым
    } else {
        loadingImage.onload = () => {
            loadingImage.style.visibility = 'visible'; // Показываем изображение после загрузки
        };
    }

    // Минимальное время отображения экрана загрузки
    setTimeout(() => {
        loadingScreen.style.opacity = '0'; // Плавное скрытие экрана
        setTimeout(() => {
            loadingScreen.style.display = 'none'; // Полное удаление экрана
        }, 500); // Ждем завершения анимации
    }, 500); // Минимальное время отображения (в миллисекундах)
});
