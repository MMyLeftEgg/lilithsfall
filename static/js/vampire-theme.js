/**
 * Vampire Theme JavaScript - Funcionalidades interativas para Lilith's Fall
 */

document.addEventListener('DOMContentLoaded', function() {
    // Inicialização do tema vampírico
    initVampireTheme();
    
    // Inicialização do modo dia/noite
    initDayNightMode();
    
    // Inicialização do sistema de notificações
    initNotifications();
    
    // Inicialização de animações
    initAnimations();
    
    // Inicialização do calendário de eventos
    initEventCalendar();
    
    // Inicialização da barra de pesquisa
    initSearchBar();
    
    // Inicialização do sistema de breadcrumbs
    initBreadcrumbs();
    
    // Inicialização do painel de estatísticas
    initStatisticsPanel();
    
    // Inicialização do menu responsivo
    initResponsiveMenu();
});

/**
 * Inicializa o tema vampírico
 */
function initVampireTheme() {
    // Adiciona a classe do tema ao body
    document.body.classList.add('vampire-theme', 'mist-bg');
    
    // Aplica classes vampíricas aos elementos
    applyVampireClasses();
    
    // Adiciona fontes temáticas se ainda não estiverem carregadas
    if (!document.getElementById('vampire-fonts')) {
        const fontLink = document.createElement('link');
        fontLink.id = 'vampire-fonts';
        fontLink.rel = 'stylesheet';
        fontLink.href = 'https://fonts.googleapis.com/css2?family=Cinzel:wght@400;700&family=Crimson+Text:ital,wght@0,400;0,600;1,400&display=swap';
        document.head.appendChild(fontLink);
    }
}

/**
 * Aplica classes vampíricas aos elementos da página
 */
function applyVampireClasses() {
    // Aplica classes aos elementos do header
    const header = document.querySelector('header');
    if (header) header.classList.add('vampire-header');
    
    // Aplica classes à barra de navegação
    const navbars = document.querySelectorAll('nav, .navbar');
    navbars.forEach(nav => nav.classList.add('vampire-nav'));
    
    // Aplica classes à sidebar
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) sidebar.classList.add('vampire-sidebar');
    
    // Aplica classes aos cards
    const cards = document.querySelectorAll('.card, .dashboard-card');
    cards.forEach(card => {
        card.classList.add('vampire-card');
        
        // Adiciona efeito de sangue a alguns cards aleatoriamente
        if (Math.random() > 0.7) {
            card.classList.add('blood-drip');
        }
    });
    
    // Aplica classes aos botões
    const buttons = document.querySelectorAll('.btn-primary, .btn-danger, .btn-dark');
    buttons.forEach(btn => btn.classList.add('btn-vampire'));
    
    // Aplica efeito de pulso aos ícones
    const icons = document.querySelectorAll('.dashboard-icon, .card-header i');
    icons.forEach(icon => icon.classList.add('pulse-icon'));
    
    // Aplica efeito de fade-in aos elementos principais
    const fadeElements = document.querySelectorAll('.dashboard-container, .welcome-message, .section-title');
    fadeElements.forEach(el => el.classList.add('fade-in'));
}

/**
 * Inicializa o modo dia/noite
 */
function initDayNightMode() {
    // Cria o botão de alternar modo dia/noite
    const dayNightToggle = document.createElement('button');
    dayNightToggle.id = 'day-night-toggle';
    dayNightToggle.className = 'btn btn-vampire position-fixed';
    dayNightToggle.style.bottom = '20px';
    dayNightToggle.style.right = '20px';
    dayNightToggle.style.zIndex = '1000';
    dayNightToggle.innerHTML = '<i class="fas fa-moon"></i>';
    dayNightToggle.title = 'Alternar modo dia/noite';
    
    // Adiciona o botão ao body
    document.body.appendChild(dayNightToggle);
    
    // Adiciona evento de clique
    dayNightToggle.addEventListener('click', function() {
        document.body.classList.toggle('day-mode');
        
        // Altera o ícone
        const icon = this.querySelector('i');
        if (document.body.classList.contains('day-mode')) {
            icon.className = 'fas fa-sun';
        } else {
            icon.className = 'fas fa-moon';
        }
        
        // Salva a preferência no localStorage
        const mode = document.body.classList.contains('day-mode') ? 'day' : 'night';
        localStorage.setItem('vampireThemeMode', mode);
    });
    
    // Verifica se há uma preferência salva
    const savedMode = localStorage.getItem('vampireThemeMode');
    if (savedMode === 'day') {
        document.body.classList.add('day-mode');
        dayNightToggle.querySelector('i').className = 'fas fa-sun';
    }
}

// Inicializar sistema de notificações
function initNotifications() {
    const notificationBell = document.getElementById('notification-bell');
    const notificationDropdown = document.getElementById('notification-dropdown');
    const notificationCount = document.getElementById('notification-count');
    const notificationsList = document.getElementById('notifications-list');
    
    if (notificationBell && notificationDropdown) {
        // Carregar notificações ao inicializar
        loadNotifications();
        
        // Atualizar notificações a cada 30 segundos
        setInterval(loadNotifications, 30000);
        
        // Mostrar dropdown apenas quando passar o mouse sobre o sino
        notificationBell.addEventListener('mouseenter', function() {
            notificationDropdown.style.display = 'block';
        });
        
        // Manter dropdown visível quando o mouse estiver sobre ele
        notificationDropdown.addEventListener('mouseenter', function() {
            notificationDropdown.style.display = 'block';
        });
        
        // Ocultar dropdown quando o mouse sair do sino e do dropdown
        notificationBell.addEventListener('mouseleave', function(e) {
            if (!e.relatedTarget || !notificationDropdown.contains(e.relatedTarget)) {
                setTimeout(function() {
                    if (!notificationDropdown.matches(':hover')) {
                        notificationDropdown.style.display = 'none';
                    }
                }, 100);
            }
        });
        
        notificationDropdown.addEventListener('mouseleave', function() {
            notificationDropdown.style.display = 'none';
        });
        
        // Adicionar evento para marcar todas como lidas
        const markAllReadBtn = document.getElementById('mark-all-read');
        if (markAllReadBtn) {
            markAllReadBtn.addEventListener('click', markAllNotificationsRead);
        }
    }
    
    // Função para carregar notificações
    function loadNotifications() {
        fetch('/notifications')
            .then(response => response.json())
            .then(notifications => {
                updateNotificationsList(notifications);
                updateNotificationCount(notifications);
            })
            .catch(error => {
                console.error('Erro ao carregar notificações:', error);
            });
    }
    
    // Função para atualizar a lista de notificações
    function updateNotificationsList(notifications) {
        if (!notificationsList) return;
        
        notificationsList.innerHTML = '';
        
        if (notifications.length === 0) {
            notificationsList.innerHTML = '<div class="dropdown-item text-center text-muted">Nenhuma notificação</div>';
            return;
        }
        
        notifications.slice(0, 5).forEach(notification => {
            const notificationItem = document.createElement('div');
            notificationItem.className = `dropdown-item notification-item ${!notification.is_read ? 'unread' : ''}`;
            notificationItem.innerHTML = `
                <div class="notification-content">
                    <strong>${notification.title}</strong>
                    <p class="mb-1">${notification.message}</p>
                    <small class="text-muted">${notification.created_at}</small>
                </div>
                <div class="notification-actions">
                    ${!notification.is_read ? `<button class="btn btn-sm btn-outline-primary mark-read" data-id="${notification.id}">Marcar como lida</button>` : ''}
                    <button class="btn btn-sm btn-outline-danger delete-notification" data-id="${notification.id}">Excluir</button>
                </div>
            `;
            
            // Adicionar eventos aos botões
            const markReadBtn = notificationItem.querySelector('.mark-read');
            if (markReadBtn) {
                markReadBtn.addEventListener('click', () => markNotificationRead(notification.id));
            }
            
            const deleteBtn = notificationItem.querySelector('.delete-notification');
            deleteBtn.addEventListener('click', () => deleteNotification(notification.id));
            
            notificationsList.appendChild(notificationItem);
        });
    }
    
    // Função para atualizar o contador de notificações
    function updateNotificationCount(notifications) {
        if (!notificationCount) return;
        
        const unreadCount = notifications.filter(n => !n.is_read).length;
        
        if (unreadCount > 0) {
            notificationCount.textContent = unreadCount > 99 ? '99+' : unreadCount;
            notificationCount.style.display = 'inline';
        } else {
            notificationCount.style.display = 'none';
        }
    }
    
    // Função para marcar notificação como lida
    function markNotificationRead(notificationId) {
        fetch(`/mark_notification_read/${notificationId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                loadNotifications();
            }
        })
        .catch(error => {
            console.error('Erro ao marcar notificação como lida:', error);
        });
    }
    
    // Função para marcar todas as notificações como lidas
    function markAllNotificationsRead() {
        fetch('/mark_all_notifications_read', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                loadNotifications();
            }
        })
        .catch(error => {
            console.error('Erro ao marcar todas as notificações como lidas:', error);
        });
    }
    
    // Função para deletar notificação
    function deleteNotification(notificationId) {
        if (confirm('Tem certeza que deseja excluir esta notificação?')) {
            fetch(`/delete_notification/${notificationId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadNotifications();
                }
            })
            .catch(error => {
                console.error('Erro ao deletar notificação:', error);
            });
        }
    }
}

/**
 * Inicializa animações adicionais
 */
function initAnimations() {
    // Adiciona animação de entrada aos cards
    const cards = document.querySelectorAll('.vampire-card');
    
    // Usa IntersectionObserver para animar os cards quando entrarem na viewport
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = 1;
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, { threshold: 0.1 });
    
    cards.forEach(card => {
        card.style.opacity = 0;
        card.style.transform = 'translateY(20px)';
        card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
        observer.observe(card);
    });
    
    // Adiciona animação de sangue escorrendo aleatoriamente
    setInterval(() => {
        const randomCard = cards[Math.floor(Math.random() * cards.length)];
        if (randomCard && !randomCard.classList.contains('blood-drip')) {
            randomCard.classList.add('blood-drip');
            
            // Remove a classe após a animação
            setTimeout(() => {
                randomCard.classList.remove('blood-drip');
            }, 5000);
        }
    }, 10000); // A cada 10 segundos
}

/**
 * Inicializa o calendário de eventos
 */
function initEventCalendar() {
    // Verifica se já existe um container de dashboard
    const dashboardContainer = document.querySelector('.dashboard-container');
    
    if (dashboardContainer) {
        // Cria o card do calendário
        const calendarRow = document.createElement('div');
        calendarRow.className = 'row mt-4';
        calendarRow.innerHTML = `
            <div class="col-md-12">
                <div class="dashboard-card vampire-card">
                    <div class="card-header">
                        <i class="fas fa-calendar-alt"></i> Calendário de Eventos
                    </div>
                    <div class="card-body">
                        <div class="event-calendar" id="event-calendar">
                            <div class="d-flex justify-content-between align-items-center mb-3">
                                <button class="btn btn-sm btn-vampire" id="prev-month"><i class="fas fa-chevron-left"></i></button>
                                <h5 class="mb-0" id="current-month">Carregando...</h5>
                                <button class="btn btn-sm btn-vampire" id="next-month"><i class="fas fa-chevron-right"></i></button>
                            </div>
                            <div class="row text-center mb-2">
                                <div class="col">Dom</div>
                                <div class="col">Seg</div>
                                <div class="col">Ter</div>
                                <div class="col">Qua</div>
                                <div class="col">Qui</div>
                                <div class="col">Sex</div>
                                <div class="col">Sáb</div>
                            </div>
                            <div id="calendar-days">
                                <!-- Os dias do calendário serão gerados dinamicamente -->
                            </div>
                        </div>
                        <div class="mt-3">
                            <h6>Próximos Eventos:</h6>
                            <ul class="list-group" id="events-list">
                                <!-- Os eventos serão gerados dinamicamente -->
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Modal para criar evento -->
            <div class="modal fade" id="createEventModal" tabindex="-1" aria-labelledby="createEventModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-dialog-centered">
                    <div class="modal-content bg-dark text-light">
                        <div class="modal-header border-danger">
                            <h5 class="modal-title" id="createEventModalLabel">Criar Novo Evento</h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <form id="eventForm">
                                <input type="hidden" id="eventDate" name="eventDate">
                                <div class="mb-3">
                                    <label for="eventTitle" class="form-label">Título do Evento</label>
                                    <input type="text" class="form-control bg-dark text-light border-danger" id="eventTitle" required>
                                </div>
                                <div class="mb-3">
                                    <label for="eventDescription" class="form-label">Descrição</label>
                                    <textarea class="form-control bg-dark text-light border-danger" id="eventDescription" rows="3"></textarea>
                                </div>
                                <div class="mb-3">
                                    <label for="eventTime" class="form-label">Horário</label>
                                    <input type="time" class="form-control bg-dark text-light border-danger" id="eventTime">
                                </div>
                            </form>
                        </div>
                        <div class="modal-footer border-danger">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                            <button type="button" class="btn btn-danger" id="saveEvent">Salvar Evento</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Adiciona o calendário após a última linha do dashboard
        dashboardContainer.appendChild(calendarRow);
        
        // Aplica classes vampíricas aos novos elementos
        applyVampireClasses();
        
        // Inicializa o calendário com funcionalidade
        initializeCalendarFunctionality();
    }
}

/**
 * Inicializa a funcionalidade do calendário
 */
function initializeCalendarFunctionality() {
    // Elementos do DOM
    const calendarDays = document.getElementById('calendar-days');
    const currentMonthElement = document.getElementById('current-month');
    const prevMonthButton = document.getElementById('prev-month');
    const nextMonthButton = document.getElementById('next-month');
    const eventsList = document.getElementById('events-list');
    const saveEventButton = document.getElementById('saveEvent');
    
    // Data atual
    let currentDate = new Date();
    let currentMonth = currentDate.getMonth();
    let currentYear = currentDate.getFullYear();
    
    // Eventos - inicializa como array vazio, será carregado do servidor
    let events = [];
    
    // Função para carregar eventos do servidor (deve ser definida fora de saveEvent)
    function loadEvents() {
        fetch('/get_events')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Erro na resposta do servidor: ' + response.status);
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    // Atualiza a lista de eventos
                    events = data.events;
                    // Atualiza o calendário
                    renderCalendar();
                    // Atualiza a lista de eventos
                    updateEventsList();
                } else {
                    console.error('Erro ao carregar eventos:', data.message);
                }
            })
            .catch(error => {
                console.error('Erro ao carregar eventos:', error);
            });
    }
    
    // Carrega os eventos ao inicializar
    loadEvents();
    
    // Renderiza o calendário
    function renderCalendar() {
        // Atualiza o título do mês
        const monthNames = ['Janeiro', 'Fevereiro', 'Março', 'Abril', 'Maio', 'Junho', 'Julho', 'Agosto', 'Setembro', 'Outubro', 'Novembro', 'Dezembro'];
        currentMonthElement.textContent = `${monthNames[currentMonth]} ${currentYear}`;
        
        // Limpa o calendário
        calendarDays.innerHTML = '';
        
        // Obtém o primeiro dia do mês
        const firstDay = new Date(currentYear, currentMonth, 1);
        const lastDay = new Date(currentYear, currentMonth + 1, 0);
        
        // Obtém o dia da semana do primeiro dia (0 = Domingo, 6 = Sábado)
        const firstDayOfWeek = firstDay.getDay();
        
        // Número total de dias no mês
        const daysInMonth = lastDay.getDate();
        
        // Cria as linhas do calendário
        let dayCount = 1;
        let calendarHTML = '';
        
        // Determina quantas semanas precisamos (máximo de 6)
        const weeksNeeded = Math.ceil((daysInMonth + firstDayOfWeek) / 7);
        
        for (let week = 0; week < weeksNeeded; week++) {
            calendarHTML += '<div class="row mb-2">';
            
            // Adiciona os dias da semana
            for (let day = 0; day < 7; day++) {
                if ((week === 0 && day < firstDayOfWeek) || dayCount > daysInMonth) {
                    // Célula vazia para dias fora do mês atual
                    calendarHTML += '<div class="col"><div class="event-day empty"></div></div>';
                } else {
                    // Formata a data para verificar eventos
                    const dateStr = `${currentYear}-${String(currentMonth + 1).padStart(2, '0')}-${String(dayCount).padStart(2, '0')}`;
                    
                    // Verifica se há eventos neste dia
                    const hasEvent = events.some(event => event.date === dateStr);
                    
                    // Adiciona a classe has-event se houver eventos
                    const eventClass = hasEvent ? 'has-event' : '';
                    
                    // Adiciona o dia com evento se necessário
                    calendarHTML += `<div class="col"><div class="event-day ${eventClass}" data-date="${dateStr}">${dayCount}</div></div>`;
                    
                    dayCount++;
                }
            }
            
            calendarHTML += '</div>';
        }
        
        // Adiciona os dias ao calendário
        calendarDays.innerHTML = calendarHTML;
        
        // Adiciona eventos de clique aos dias
        const dayElements = document.querySelectorAll('.event-day:not(.empty)');
        dayElements.forEach(day => {
            day.addEventListener('click', function() {
                const dateStr = this.getAttribute('data-date');
                openCreateEventModal(dateStr);
            });
        });
        
        // Atualiza a lista de eventos
        updateEventsList();
    }
    
    // Atualiza a lista de eventos
    function updateEventsList() {
        // Limpa a lista de eventos
        eventsList.innerHTML = '';
        
        // Filtra eventos do mês atual
        const currentMonthStr = String(currentMonth + 1).padStart(2, '0');
        const monthEvents = events.filter(event => {
            return event.date.startsWith(`${currentYear}-${currentMonthStr}`);
        });
        
        // Ordena eventos por data
        monthEvents.sort((a, b) => a.date.localeCompare(b.date));
        
        // Adiciona eventos à lista
        if (monthEvents.length > 0) {
            monthEvents.forEach(event => {
                const day = event.date.split('-')[2];
                const li = document.createElement('li');
                li.className = 'list-group-item bg-dark text-light border-danger';
                li.textContent = `${day}/${currentMonthStr} - ${event.title}`;
                li.title = event.description || '';
                eventsList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.className = 'list-group-item bg-dark text-light border-danger';
            li.textContent = 'Nenhum evento neste mês';
            eventsList.appendChild(li);
        }
    }
    
    // Abre o modal para criar evento
    function openCreateEventModal(dateStr) {
        const modalElement = document.getElementById('createEventModal');
        if (!modalElement) {
            console.error('Modal não encontrado');
            return;
        }
        
        // Verificar se já existe um evento para esta data
        const existingEvent = events.find(event => event.date === dateStr);
        
        // Definir o valor da data no campo oculto
        const eventDateInput = document.getElementById('eventDate');
        if (eventDateInput) {
            eventDateInput.value = dateStr;
        }
        
        // Formatar a data para exibição
        const dateParts = dateStr.split('-');
        const formattedDate = `${dateParts[2]}/${dateParts[1]}/${dateParts[0]}`;
        
        // Atualizar o título do modal
        const modalLabel = document.getElementById('createEventModalLabel');
        if (modalLabel) {
            modalLabel.textContent = existingEvent ? 
                `Editar Evento para ${formattedDate}` : 
                `Criar Evento para ${formattedDate}`;
        }
        
        // Preencher os campos do formulário
        const eventTitleInput = document.getElementById('eventTitle');
        const eventDescriptionInput = document.getElementById('eventDescription');
        const eventTimeInput = document.getElementById('eventTime');
        
        if (eventTitleInput && eventDescriptionInput && eventTimeInput) {
            if (existingEvent) {
                eventTitleInput.value = existingEvent.title || '';
                eventDescriptionInput.value = existingEvent.description || '';
                eventTimeInput.value = existingEvent.time || '';
            } else {
                eventTitleInput.value = '';
                eventDescriptionInput.value = '';
                eventTimeInput.value = '';
            }
        }
        
        // Usar try-catch para evitar que a página trave se houver algum erro
        try {
            // Verificar se o Bootstrap está disponível
            if (typeof bootstrap !== 'undefined') {
                // CORREÇÃO: Verificar instância existente antes de criar nova
                let modal = bootstrap.Modal.getInstance(modalElement);
                if (!modal) {
                    modal = new bootstrap.Modal(modalElement, {
                        backdrop: 'static',
                        keyboard: false
                    });
                }
                modal.show();
            } else {
                console.error('Bootstrap não está disponível');
                // Fallback para mostrar modal sem Bootstrap
                modalElement.style.display = 'block';
                modalElement.classList.add('show');
            }
        } catch (error) {
            console.error('Erro ao abrir o modal:', error);
            alert('Houve um erro ao abrir o modal. Por favor, tente novamente.');
        }
    }
    
    // Salva um novo evento ou atualiza um existente
    function saveEvent() {
        const eventDateInput = document.getElementById('eventDate');
        const eventTitleInput = document.getElementById('eventTitle');
        const eventDescriptionInput = document.getElementById('eventDescription');
        const eventTimeInput = document.getElementById('eventTime');
        
        if (!eventDateInput || !eventTitleInput || !eventDescriptionInput || !eventTimeInput) {
            console.error('Campos do formulário não encontrados');
            return;
        }
        
        const dateStr = eventDateInput.value;
        const title = eventTitleInput.value.trim();
        const description = eventDescriptionInput.value.trim();
        const time = eventTimeInput.value;
        
        if (!title) {
            alert('Por favor, insira um título para o evento.');
            return;
        }
        
        // Preparar dados para enviar ao servidor
        const eventData = {
            date: dateStr,
            title: title,
            description: description,
            time: time
        };
        
        // Enviar dados para o servidor
        fetch('/save_event', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(eventData)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Erro na resposta do servidor: ' + response.status);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Fechar o modal
                const modalElement = document.getElementById('createEventModal');
                if (modalElement) {
                    try {
                        const modal = bootstrap.Modal.getInstance(modalElement);
                        if (modal) {
                            modal.hide();
                        } else {
                            // Tenta fechar o modal de outra forma
                            const backdropElement = document.querySelector('.modal-backdrop');
                            if (backdropElement) backdropElement.remove();
                            document.body.classList.remove('modal-open');
                            document.body.style.overflow = '';
                            document.body.style.paddingRight = '';
                            modalElement.style.display = 'none';
                            modalElement.classList.remove('show');
                        }
                    } catch (error) {
                        console.error('Erro ao fechar o modal:', error);
                    }
                }
                
                // Carrega eventos do servidor
                loadEvents();
                
                // Exibe mensagem de sucesso
                const alertDiv = document.createElement('div');
                alertDiv.className = 'alert alert-success alert-dismissible fade show mt-3';
                alertDiv.innerHTML = `
                    ${data.message}
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                `;
                
                // Adiciona a mensagem ao container do calendário
                const calendarContainer = document.querySelector('.event-calendar').parentNode;
                calendarContainer.prepend(alertDiv);
                
                // Remove a mensagem após 5 segundos
                setTimeout(() => {
                    alertDiv.remove();
                }, 5000);
            } else {
                alert('Erro ao salvar evento: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Erro ao salvar evento:', error);
            alert('Erro ao salvar evento: ' + error.message);
        });
    }
    
    // Adicione esta chamada no final da função initializeCalendarFunctionality
    // logo após renderCalendar();
    loadEvents();
    
    // Event listeners
    prevMonthButton.addEventListener('click', function() {
        currentMonth--;
        if (currentMonth < 0) {
            currentMonth = 11;
            currentYear--;
        }
        renderCalendar();
    });
    
    nextMonthButton.addEventListener('click', function() {
        currentMonth++;
        if (currentMonth > 11) {
            currentMonth = 0;
            currentYear++;
        }
        renderCalendar();
    });
    
    saveEventButton.addEventListener('click', saveEvent);
    
    // Renderiza o calendário inicial
    renderCalendar();
}

/**
 * Inicializa a barra de pesquisa
 */
function initSearchBar() {
    // Verifica se já existe uma barra de navegação
    const navbar = document.querySelector('nav');
    
    if (navbar) {
        // Cria o formulário de pesquisa
        const searchForm = document.createElement('form');
        searchForm.className = 'd-flex ms-auto me-3';
        searchForm.action = '#';
        searchForm.method = 'get';
        
        // Cria o input de pesquisa
        const searchInput = document.createElement('input');
        searchInput.type = 'search';
        searchInput.className = 'form-control search-vampire me-2';
        searchInput.placeholder = 'Pesquisar...';
        searchInput.setAttribute('aria-label', 'Pesquisar');
        
        // Cria o botão de pesquisa
        const searchButton = document.createElement('button');
        searchButton.type = 'submit';
        searchButton.className = 'btn btn-vampire';
        searchButton.innerHTML = '<i class="fas fa-search"></i>';
        
        // Adiciona os elementos ao formulário
        searchForm.appendChild(searchInput);
        searchForm.appendChild(searchButton);
        
        // Adiciona o formulário à barra de navegação
        const navbarList = navbar.querySelector('ul:first-child');
        if (navbarList) {
            navbar.insertBefore(searchForm, navbarList.nextSibling);
        } else {
            navbar.appendChild(searchForm);
        }
    }
}

/**
 * Inicializa o sistema de breadcrumbs
 */
function initBreadcrumbs() {
    // Verifica se já existe um container de dashboard
    const dashboardContainer = document.querySelector('.dashboard-container');
    
    if (dashboardContainer) {
        // Cria o elemento de breadcrumbs
        const breadcrumbs = document.createElement('nav');
        breadcrumbs.setAttribute('aria-label', 'breadcrumb');
        breadcrumbs.className = 'mb-4';
        
        // Cria a lista de breadcrumbs
        const breadcrumbList = document.createElement('ol');
        breadcrumbList.className = 'breadcrumb breadcrumb-vampire p-2';
        
        // Adiciona os itens de breadcrumb
        breadcrumbList.innerHTML = `
            <li class="breadcrumb-item"><a href="/" class="text-decoration-none text-light">Home</a></li>
            <li class="breadcrumb-item"><a href="/dashboard" class="text-decoration-none text-light">Dashboard</a></li>
            <li class="breadcrumb-item active" aria-current="page">Visão Geral</li>
        `;
        
        breadcrumbs.appendChild(breadcrumbList);
        
        // Insere os breadcrumbs no início do container
        dashboardContainer.insertBefore(breadcrumbs, dashboardContainer.firstChild);
    }
}

/**
 * Inicializa o painel de estatísticas personalizadas
 */
function initStatisticsPanel() {
    // Verifica se já existe um container de dashboard
    const dashboardContainer = document.querySelector('.dashboard-container');
    
    if (dashboardContainer) {
        // Cria o card de estatísticas personalizadas
        const statsRow = document.createElement('div');
        statsRow.className = 'row mt-4';
        statsRow.innerHTML = `
            <div class="col-md-12">
                <div class="dashboard-card vampire-card">
                    <div class="card-header">
                        <i class="fas fa-chart-pie"></i> Estatísticas Pessoais
                    </div>
                    <div class="card-body">
                        <div class="row text-center">
                            <div class="col-md-3 mb-3">
                                <div class="stat-circle">
                                    <div class="stat-value">85%</div>
                                </div>
                                <h5 class="mt-3">Reputação</h5>
                                <p class="text-muted">Sua influência no mundo das sombras</p>
                            </div>
                            <div class="col-md-3 mb-3">
                                <div class="stat-circle">
                                    <div class="stat-value">12</div>
                                </div>
                                <h5 class="mt-3">Aliados</h5>
                                <p class="text-muted">Contatos que podem ajudá-lo</p>
                            </div>
                            <div class="col-md-3 mb-3">
                                <div class="stat-circle">
                                    <div class="stat-value">7</div>
                                </div>
                                <h5 class="mt-3">Inimigos</h5>
                                <p class="text-muted">Aqueles que buscam sua queda</p>
                            </div>
                            <div class="col-md-3 mb-3">
                                <div class="stat-circle">
                                    <div class="stat-value">3</div>
                                </div>
                                <h5 class="mt-3">Territórios</h5>
                                <p class="text-muted">Áreas sob seu controle</p>
                            </div>
                        </div>
                        <div class="progress mt-4">
                            <div class="progress-bar bg-danger" role="progressbar" style="width: 65%" aria-valuenow="65" aria-valuemin="0" aria-valuemax="100">Sede de Sangue: 65%</div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Adiciona o painel de estatísticas após a última linha do dashboard
        dashboardContainer.appendChild(statsRow);
        
        // Aplica classes vampíricas aos novos elementos
        applyVampireClasses();
    }
}

/**
 * Inicializa o menu responsivo
 */
function initResponsiveMenu() {
    // Verifica se já existe uma sidebar
    const sidebar = document.querySelector('.sidebar');
    const content = document.querySelector('.content');
    
    if (sidebar && content) {
        // Cria o botão de toggle para a sidebar
        const toggleButton = document.createElement('button');
        toggleButton.className = 'btn btn-vampire sidebar-toggle d-md-none';
        toggleButton.style.position = 'fixed';
        toggleButton.style.top = '10px';
        toggleButton.style.left = '10px';
        toggleButton.style.zIndex = '1050';
        toggleButton.innerHTML = '<i class="fas fa-bars"></i>';
        
        // Adiciona o botão ao body
        document.body.appendChild(toggleButton);
        
        // Adiciona evento de clique
        toggleButton.addEventListener('click', function() {
            sidebar.classList.toggle('expanded');
            content.classList.toggle('sidebar-expanded');
            
            // Altera o ícone
            const icon = this.querySelector('i');
            if (sidebar.classList.contains('expanded')) {
                icon.className = 'fas fa-times';
            } else {
                icon.className = 'fas fa-bars';
            }
        });
        
        // Fecha a sidebar ao clicar em um link (em dispositivos móveis)
        const sidebarLinks = sidebar.querySelectorAll('a');
        sidebarLinks.forEach(link => {
            link.addEventListener('click', function() {
                if (window.innerWidth < 768) {
                    sidebar.classList.remove('expanded');
                    content.classList.remove('sidebar-expanded');
                    toggleButton.querySelector('i').className = 'fas fa-bars';
                }
            });
        });
    }
}
// No final da função initializeCalendarFunctionality

// Adiciona evento de clique ao botão de salvar
if (saveEventButton) {
    saveEventButton.addEventListener('click', saveEvent);
}

// Adiciona eventos de clique aos botões de navegação
if (prevMonthButton) {
    prevMonthButton.addEventListener('click', function() {
        currentMonth--;
        if (currentMonth < 0) {
            currentMonth = 11;
            currentYear--;
        }
        renderCalendar();
        updateEventsList();
    });
}

if (nextMonthButton) {
    nextMonthButton.addEventListener('click', function() {
        currentMonth++;
        if (currentMonth > 11) {
            currentMonth = 0;
            currentYear++;
        }
        renderCalendar();
        updateEventsList();
    });
}

// Adicionar debounce para pesquisa
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Implementar pesquisa em tempo real
function initLiveSearch() {
    const searchInput = document.querySelector('.search-vampire');
    if (searchInput) {
        const debouncedSearch = debounce(function(query) {
            if (query.length > 2) {
                fetch(`/search?q=${encodeURIComponent(query)}`)
                    .then(response => response.json())
                    .then(data => {
                        // Atualizar resultados na página
                        updateSearchResults(data);
                    });
            }
        }, 300);
        
        searchInput.addEventListener('input', function() {
            debouncedSearch(this.value);
        });
    }
}

function openCreateEventModal(date) {
    const modal = document.getElementById('createEventModal');
    if (!modal) return;
    
    // Limpar instância anterior se existir
    const existingInstance = bootstrap.Modal.getInstance(modal);
    if (existingInstance) {
        existingInstance.dispose();
    }
    
    // Criar nova instância
    const modalInstance = new bootstrap.Modal(modal);
    modalInstance.show();
}

function initLiveSearch() {
    const searchInput = document.getElementById('searchInput');
    if (!searchInput) return;
    
    let searchTimeout;
    
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        const query = this.value.trim();
        
        if (query.length < 2) {
            hideSearchResults();
            return;
        }
        
        searchTimeout = setTimeout(() => {
            fetch(`/search?q=${encodeURIComponent(query)}`)
                .then(response => response.json())
                .then(data => displaySearchResults(data))
                .catch(error => console.error('Erro na busca:', error));
        }, 300);
    });
}

function displaySearchResults(results) {
    const resultsContainer = document.getElementById('searchResults');
    if (!resultsContainer) return;
    
    let html = '';
    
    if (results.characters.length > 0) {
        html += '<h6>Personagens</h6>';
        results.characters.forEach(char => {
            html += `<a href="/character_detail/${char.id}" class="search-result-item">${char.name}</a>`;
        });
    }
    
    if (results.adventures.length > 0) {
        html += '<h6>Aventuras</h6>';
        results.adventures.forEach(adv => {
            html += `<a href="/adventure_detail/${adv.id}" class="search-result-item">${adv.title}</a>`;
        });
    }
    
    resultsContainer.innerHTML = html;
    resultsContainer.style.display = 'block';
}
function initLiveSearch() {
    const searchInput = document.getElementById('searchInput');
    if (!searchInput) return;
    
    let searchTimeout;
    
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        const query = this.value.trim();
        
        if (query.length < 2) {
            hideSearchResults();
            return;
        }
        
        searchTimeout = setTimeout(() => {
            fetch(`/search?q=${encodeURIComponent(query)}`)
                .then(response => response.json())
                .then(data => displaySearchResults(data))
                .catch(error => console.error('Erro na busca:', error));
        }, 300);
    });
}

function displaySearchResults(results) {
    const resultsContainer = document.getElementById('searchResults');
    if (!resultsContainer) return;
    
    let html = '';
    
    if (results.characters.length > 0) {
        html += '<h6>Personagens</h6>';
        results.characters.forEach(char => {
            html += `<a href="/character_detail/${char.id}" class="search-result-item">${char.name}</a>`;
        });
    }
    
    if (results.adventures.length > 0) {
        html += '<h6>Aventuras</h6>';
        results.adventures.forEach(adv => {
            html += `<a href="/adventure_detail/${adv.id}" class="search-result-item">${adv.title}</a>`;
        });
    }
    
    resultsContainer.innerHTML = html;
    resultsContainer.style.display = 'block';
}function initLiveSearch() {
    const searchInput = document.getElementById('searchInput');
    if (!searchInput) return;
    
    let searchTimeout;
    
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        const query = this.value.trim();
        
        if (query.length < 2) {
            hideSearchResults();
            return;
        }
        
        searchTimeout = setTimeout(() => {
            fetch(`/search?q=${encodeURIComponent(query)}`)
                .then(response => response.json())
                .then(data => displaySearchResults(data))
                .catch(error => console.error('Erro na busca:', error));
        }, 300);
    });
}

function displaySearchResults(results) {
    const resultsContainer = document.getElementById('searchResults');
    if (!resultsContainer) return;
    
    let html = '';
    
    if (results.characters.length > 0) {
        html += '<h6>Personagens</h6>';
        results.characters.forEach(char => {
            html += `<a href="/character_detail/${char.id}" class="search-result-item">${char.name}</a>`;
        });
    }
    
    if (results.adventures.length > 0) {
        html += '<h6>Aventuras</h6>';
        results.adventures.forEach(adv => {
            html += `<a href="/adventure_detail/${adv.id}" class="search-result-item">${adv.title}</a>`;
        });
    }
    
    resultsContainer.innerHTML = html;
    resultsContainer.style.display = 'block';
}function initLiveSearch() {
    const searchInput = document.getElementById('searchInput');
    if (!searchInput) return;
    
    let searchTimeout;
    
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        const query = this.value.trim();
        
        if (query.length < 2) {
            hideSearchResults();
            return;
        }
        
        searchTimeout = setTimeout(() => {
            fetch(`/search?q=${encodeURIComponent(query)}`)
                .then(response => response.json())
                .then(data => displaySearchResults(data))
                .catch(error => console.error('Erro na busca:', error));
        }, 300);
    });
}

function displaySearchResults(results) {
    const resultsContainer = document.getElementById('searchResults');
    if (!resultsContainer) return;
    
    let html = '';
    
    if (results.characters.length > 0) {
        html += '<h6>Personagens</h6>';
        results.characters.forEach(char => {
            html += `<a href="/character_detail/${char.id}" class="search-result-item">${char.name}</a>`;
        });
    }
    
    if (results.adventures.length > 0) {
        html += '<h6>Aventuras</h6>';
        results.adventures.forEach(adv => {
            html += `<a href="/adventure_detail/${adv.id}" class="search-result-item">${adv.title}</a>`;
        });
    }
    
    resultsContainer.innerHTML = html;
    resultsContainer.style.display = 'block';
}
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} notification-toast`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.add('show');
    }, 100);
    
    setTimeout(() => {
        notification.remove();
    }, 5000);
}