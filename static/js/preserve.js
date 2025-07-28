const form = document.querySelector('form');

// Обработчик движения мыши
form.addEventListener('mousemove', (event) => {
    const rect = form.getBoundingClientRect();
    const x = event.clientX - rect.left; // Положение мыши по оси X внутри формы
    const y = event.clientY - rect.top;  // Положение мыши по оси Y внутри формы

    const centerX = rect.width / 2; // Центр формы по оси X
    const centerY = rect.height / 2; // Центр формы по оси Y

    const rotateX = -(y - centerY) / 10; // Вычисление угла наклона по оси X
    const rotateY = (x - centerX) / 10; // Вычисление угла наклона по оси Y

    form.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
});

// Обработчик выхода мыши за пределы формы (сброс)
form.addEventListener('mouseleave', () => {
    form.style.transform = 'perspective(1000px) rotateX(0) rotateY(0)';
});

