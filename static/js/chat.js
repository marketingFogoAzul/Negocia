/* eslint-disable no-unused-vars */

const ChatModule = (function () {

    // Elementos do DOM
    let chatWindow, chatInput, sendButton, reviewButtonContainer, reviewButton;
    let closeButton, disableIaButton;
    let chatHeader, chatStatusText, inputArea;

    // Estado do Chat
    let currentChatId = null;
    let chatStatus = 'active';
    let reviewRequested = false; // Flag para "botão já clicado"
    let userRole = 0;
    let userName = 'Usuário';

    /**
     * Inicializa o módulo
     */
    function init(config) {
        // Mapeia os elementos do DOM
        chatWindow = document.getElementById('chat-window');
        chatInput = document.getElementById('chat-input');
        sendButton = document.getElementById('send-button');
        reviewButtonContainer = document.getElementById('review-button-container');
        reviewButton = document.getElementById('review-button');
        closeButton = document.getElementById('close-chat-button');
        disableIaButton = document.getElementById('disable-ia-button');
        chatHeader = document.getElementById('chat-header');
        chatStatusText = document.getElementById('chat-status');
        inputArea = document.getElementById('input-area');

        // Configura o estado
        currentChatId = config.chatId || null;
        chatStatus = config.status || 'active';
        reviewRequested = config.reviewRequested || false; // Pega do backend
        userRole = config.userRole || 0;
        userName = config.userName || 'Usuário';

        // Adiciona os Event Listeners
        if (sendButton) {
            sendButton.addEventListener('click', handleSendMessage);
        }
        if (chatInput) {
            chatInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSendMessage();
                }
            });
             // Ajusta altura ao carregar
            autoResizeTextarea(chatInput);
             chatInput.addEventListener('input', () => autoResizeTextarea(chatInput));
        }
        if (reviewButton) {
            reviewButton.addEventListener('click', handleRequestReview);
        }
        if (closeButton) {
            closeButton.addEventListener('click', handleCloseChat);
        }
        if (disableIaButton) {
            disableIaButton.addEventListener('click', handleDisableIa);
        }

        scrollToBottom();
        updateChatUI();
    }

     /** Auto-resize textarea */
    function autoResizeTextarea(textarea) {
        textarea.style.height = 'auto'; // Reseta altura
        // Define a nova altura baseada no scrollHeight, mas não menor que a inicial
        textarea.style.height = Math.max(42, textarea.scrollHeight) + 'px';
    }


    /**
     * Atualiza a UI baseada no status do chat
     */
    function updateChatUI() {

        // --- Lógica do Botão de Revisão (Usuário) ---
        if (reviewButtonContainer) {
            // Mostra se o chat está ativo, user é consumidor E revisão NUNCA foi pedida
            const canRequestReview = chatStatus === 'active' && userRole === 0 && !reviewRequested;
            if (canRequestReview) {
                reviewButtonContainer.classList.remove('hidden');
            } else {
                reviewButtonContainer.classList.add('hidden');
            }
        }

        // --- Lógica dos Botões de Admin (Vendedor) ---
        // Só mostra se for admin E chat estiver 'assumido' ou 'manual'
        const showAdminButtons = userRole >= 1 && (chatStatus === 'assumed' || chatStatus === 'manual_override');

        if (disableIaButton) {
            if (showAdminButtons) {
                disableIaButton.classList.remove('hidden');
                disableIaButton.textContent = chatStatus === 'manual_override' ? 'IA Desativada' : 'Desativar IA';
                disableIaButton.disabled = chatStatus === 'manual_override';
            } else {
                disableIaButton.classList.add('hidden');
            }
        }

        if (closeButton) {
            // Mostra se for admin e o chat não estiver completo
            if (userRole >= 1 && chatStatus !== 'completed') {
                closeButton.classList.remove('hidden');
            } else {
                closeButton.classList.add('hidden');
            }
        }

        // --- Lógica da Barra de Digitação ---
        if (chatInput) {
            let placeholder = 'Digite sua mensagem...';
            let disabled = false;

            if (chatStatus === 'completed') {
                placeholder = 'Esta negociação foi encerrada.';
                disabled = true;
            } else if (chatStatus === 'pending_review' && userRole === 0) {
                placeholder = 'Aguardando resposta do vendedor...';
                disabled = true;
            } else if (chatStatus === 'pending_review' && userRole >= 1) {
                 // Admin pode responder para assumir um chat pendente
                placeholder = 'Responda para assumir este atendimento...';
                disabled = false;
            } else if (chatStatus === 'active' || chatStatus === 'assumed' || chatStatus === 'manual_override') {
                 placeholder = 'Digite sua mensagem...';
                 disabled = false;
            }

            chatInput.disabled = disabled;
            chatInput.placeholder = placeholder;
            sendButton.disabled = disabled;
        }

        // --- Texto do Status ---
        if (chatStatusText) {
            const statusTexts = {
                'active': 'Negociação em andamento',
                'pending_review': 'Aguardando revisão',
                'assumed': 'Em atendimento',
                'manual_override': 'IA Desativada - Atendimento Manual',
                'completed': 'Negociação Encerrada'
            };
            chatStatusText.textContent = statusTexts[chatStatus] || 'Negociação em andamento';
        }
    }

    /**
     * Adiciona uma mensagem à janela do chat
     */
    function addMessageToWindow(msg) {
        if (!chatWindow) return;
        removeLoadingBubble();

        const isScrolledToBottom = chatWindow.scrollHeight - chatWindow.clientHeight <= chatWindow.scrollTop + 1;

        // Mensagens do sistema (centralizadas)
        if (msg.sender_type === 'system') {
            const systemDiv = document.createElement('div');
            systemDiv.classList.add('message-container', 'system');
            systemDiv.innerHTML = `<div class="message-bubble">${msg.text}</div>`;
            chatWindow.appendChild(systemDiv);
            if (isScrolledToBottom) scrollToBottom(); // Só rola se já estava no fim
            return;
        }

        const container = document.createElement('div');
        container.classList.add('message-container', msg.sender_type);

        // Define avatar
        let avatarContent = '';
        if (msg.sender_type === 'user') {
            avatarContent = '👤'; // Avatar padrão do usuário
        } else {
            // Bot ou Admin usam o logo
            avatarContent = `<img src="/static/img/logo.png" alt="logo">`;
        }

        // Define nome do remetente
        let senderName = '';
        if (msg.sender_type === 'admin') {
            senderName = `<div class="message-sender-name">${msg.sender_name || 'Vendedor'}</div>`;
        } else if (msg.sender_type === 'user') {
            senderName = `<div class="message-sender-name">${userName}</div>`;
        }

        container.innerHTML = `
            <div class="profile-pic">${avatarContent}</div>
            <div class="message-content">
                ${senderName}
                <div class="message-bubble">
                    ${msg.text.replace(/\n/g, '<br>')}
                </div>
            </div>
        `;

        chatWindow.appendChild(container);
        if (isScrolledToBottom) scrollToBottom(); // Só rola se já estava no fim
    }

    /** Mostra o "digitando..." do bot */
    function showLoadingBubble() {
        removeLoadingBubble(); // Garante que só haja um
        const isScrolledToBottom = chatWindow.scrollHeight - chatWindow.clientHeight <= chatWindow.scrollTop + 1;

        const container = document.createElement('div');
        container.classList.add('message-container', 'bot', 'loading-bubble');
        container.innerHTML = `
            <div class="profile-pic">
                <img src="/static/img/logo.png" alt="logo">
            </div>
            <div class="message-content">
                <div class="message-bubble">
                    <div class="loading-dots">
                        <span></span><span></span><span></span>
                    </div>
                </div>
            </div>
        `;
        chatWindow.appendChild(container);
        if (isScrolledToBottom) scrollToBottom(); // Só rola se já estava no fim
    }

    /** Remove o "digitando..." */
    function removeLoadingBubble() {
        const loading = chatWindow.querySelector('.loading-bubble');
        if (loading) {
            loading.remove();
        }
    }

    /** Rola o chat para a última mensagem */
    function scrollToBottom() {
        if (chatWindow) {
            chatWindow.scrollTop = chatWindow.scrollHeight;
        }
    }

    /** Lida com o envio de mensagem (User ou Admin) */
    async function handleSendMessage() {
        const messageText = chatInput.value.trim();
        if (messageText === '' || chatInput.disabled) {
            return;
        }

        const isAdmin = userRole >= 1;
        const url = isAdmin
            ? `/api/chat/admin_message/${currentChatId}`
            : '/api/chat/user_message';

        const body = { message: messageText };
        if (!isAdmin && currentChatId) { // Só envia chat_id se já existir
            body.chat_id = currentChatId;
        }

        // Adiciona a mensagem do usuário/admin imediatamente
        addMessageToWindow({
            sender_type: isAdmin ? 'admin' : 'user',
            text: messageText,
            sender_name: userName // Nome do usuário logado
        });

        const oldMessage = chatInput.value;
        chatInput.value = '';
        autoResizeTextarea(chatInput); // Ajusta altura após limpar
        chatInput.disabled = true;
        sendButton.disabled = true;

        if (!isAdmin) {
            showLoadingBubble();
        }

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || `Erro ${response.status}`);
            }

            removeLoadingBubble();

            // Atualiza o ID do chat se for a primeira mensagem (retorno do backend)
            if (data.chat_id && !currentChatId) {
                currentChatId = data.chat_id;
                if (chatHeader) {
                    chatHeader.classList.remove('hidden');
                    document.getElementById('chat-header-id').textContent = currentChatId;
                }
                window.history.pushState({}, '', `/chat/${currentChatId}`);
            }

            // Adiciona a resposta (do bot ou sistema)
            if (data.sender_type && data.sender_type !== (isAdmin ? 'admin' : 'user')) { // Evita duplicar msg enviada
                addMessageToWindow(data);
            }

            // Atualiza status se o backend enviar um novo
            if (data.chat_status) {
                chatStatus = data.chat_status;
                updateChatUI();
            }

        } catch (error) {
            console.error('Erro ao enviar mensagem:', error);
            removeLoadingBubble();
            addMessageToWindow({
                sender_type: 'system',
                text: 'Erro de conexão. Por favor, tente novamente.'
            });
            chatInput.value = oldMessage; // Restaura msg
            autoResizeTextarea(chatInput); // Ajusta altura
        } finally {
            // Re-ativa a input se o chat não estiver bloqueado
             updateChatUI(); // Atualiza estado dos botões/input baseado no status
             if (!chatInput.disabled) {
                 chatInput.focus();
             }
        }
    }

    /** Botão 'Solicitar Revisão' (Usuário) */
    async function handleRequestReview() {
        if (!currentChatId || reviewButton.disabled) return;

        reviewButton.disabled = true;
        reviewButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enviando...';

        try {
            const response = await fetch(`/api/chat/request_review/${currentChatId}`, {
                method: 'POST'
            });
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message);
            }

            addMessageToWindow({
                sender_type: data.sender_type, // 'system'
                text: data.message
            });

            chatStatus = 'pending_review';
            reviewRequested = true; // Marca como clicado
            updateChatUI(); // Esconde botão, bloqueia input do user

        } catch (error) {
            alert('Erro: ' + error.message);
            // Reabilita o botão apenas se o erro ocorreu
            reviewButton.disabled = false;
            reviewButton.innerHTML = '<i class="fas fa-gavel"></i> Solicitar Revisão da Proposta';
        }
    }

    /** Botão 'Desativar IA' (Admin) */
    async function handleDisableIa() {
        if (!currentChatId || disableIaButton.disabled) return;
        if (!confirm('Tem certeza que deseja desativar a IA? O atendimento será 100% manual.')) {
            return;
        }

        disableIaButton.disabled = true;
        disableIaButton.textContent = '...';

        try {
            const response = await fetch(`/api/chat/disable_ia/${currentChatId}`, {
                method: 'POST'
            });
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message);
            }

            addMessageToWindow({
                sender_type: data.sender_type, // 'system'
                text: data.message
            });

            chatStatus = 'manual_override';
            updateChatUI(); // Atualiza texto e estado do botão

        } catch (error) {
            alert('Erro: ' + error.message);
            updateChatUI(); // Re-habilita com texto correto se der erro
        }
    }

   /** Botão 'Encerrar Negociação' (Admin) */
    async function handleCloseChat() {
        if (!currentChatId || closeButton.disabled) return;
        if (!confirm('Tem certeza que deseja ENCERRAR esta negociação? Esta ação não pode ser desfeita.')) {
            return;
        }

        closeButton.disabled = true;
        closeButton.textContent = '...';

        try {
            const response = await fetch(`/api/chat/close/${currentChatId}`, {
                method: 'POST'
            });
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message);
            }

            addMessageToWindow({
                sender_type: data.sender_type, // 'system'
                text: data.message
            });

            chatStatus = 'completed';
            updateChatUI(); // Desativa input e botões

        } catch (error) {
            alert('Erro: ' + error.message); // Corrigido
            closeButton.disabled = false;
            closeButton.textContent = 'Encerrar Negociação';
        }
    }

    // Expõe a função de inicialização
    return {
        init: init
    };
})();