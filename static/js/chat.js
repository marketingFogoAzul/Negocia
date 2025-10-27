/* eslint-disable no-unused-vars */

const ChatModule = (function () {

    // Elementos do DOM
    let chatWindow, chatInput, sendButton, reviewButtonContainer, reviewButton;
    let closeButton, disableIaButton;
    let chatHeader, chatStatusText, inputArea;
    
    // Estado do Chat
    let currentChatId = null;
    let chatStatus = 'active';
    let userProfilePic = 'default_user.png';
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
        inputArea = document.getElementById('chat-input-row');
        
        // Configura o estado
        currentChatId = config.chatId || null;
        chatStatus = config.status || 'active';
        userProfilePic = config.userPic || 'default_user.png';
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

    /**
     * Atualiza a UI baseada no status do chat
     */
    function updateChatUI() {
        const isAdmin = document.body.dataset.isAdmin === 'true';
        const userRole = parseInt(document.body.dataset.userRole) || 0;
        
        // Esconde/mostra botões baseado no status e permissões
        if (reviewButtonContainer) {
            if (chatStatus === 'active' && userRole === 0) {
                reviewButtonContainer.classList.remove('hidden');
            } else {
                reviewButtonContainer.classList.add('hidden');
            }
        }
        
        if (disableIaButton) {
            if ((chatStatus === 'assumed' || chatStatus === 'active') && userRole >= 1) {
                disableIaButton.classList.remove('hidden');
                disableIaButton.textContent = chatStatus === 'manual_override' ? 'IA Desativada' : 'Desativar IA';
                disableIaButton.disabled = chatStatus === 'manual_override';
            } else {
                disableIaButton.classList.add('hidden');
            }
        }
        
        if (closeButton) {
            if (userRole >= 1 && chatStatus !== 'completed') {
                closeButton.classList.remove('hidden');
            } else {
                closeButton.classList.add('hidden');
            }
        }
        
        // Atualiza placeholder e status
        if (chatInput) {
            if (chatStatus === 'completed') {
                chatInput.disabled = true;
                chatInput.placeholder = 'Esta negociação foi encerrada.';
            } else if (chatStatus === 'pending_review' || chatStatus === 'assumed' || chatStatus === 'manual_override') {
                chatInput.disabled = false;
                chatInput.placeholder = 'Aguardando resposta do vendedor...';
            } else {
                chatInput.disabled = false;
                chatInput.placeholder = 'Digite sua mensagem...';
            }
        }
        
        // Atualiza texto do status
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

        // Mensagens do sistema
        if (msg.sender_type === 'system') {
            const systemDiv = document.createElement('div');
            systemDiv.classList.add('message-container', 'system');
            systemDiv.innerHTML = `<div class="message-bubble">${msg.text}</div>`;
            chatWindow.appendChild(systemDiv);
            scrollToBottom();
            return;
        }

        const container = document.createElement('div');
        container.classList.add('message-container', msg.sender_type);

        // Define avatar
        let avatarContent = '';
        if (msg.sender_type === 'user') {
            avatarContent = '👤';
        } else {
            avatarContent = '<img src="/static/img/logo.png" alt="bot" style="width: 100%; height: 100%; border-radius: 50%;">';
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
        scrollToBottom();
    }

    /**
     * Mostra o "digitando..." do bot
     */
    function showLoadingBubble() {
        removeLoadingBubble();
        const container = document.createElement('div');
        container.classList.add('message-container', 'bot', 'loading-bubble');
        container.innerHTML = `
            <div class="profile-pic">
                <img src="/static/img/logo.png" alt="bot" style="width: 100%; height: 100%; border-radius: 50%;">
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
        scrollToBottom();
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

    /** Lida com o envio de mensagem */
    async function handleSendMessage() {
        const messageText = chatInput.value.trim();
        if (messageText === '' || chatStatus === 'completed') {
            return;
        }

        const isAdmin = document.body.dataset.isAdmin === 'true';
        const url = isAdmin 
            ? `/api/chat/admin_message/${currentChatId}`
            : '/api/chat/user_message';
        
        const body = { message: messageText };
        if (!isAdmin) {
            body.chat_id = currentChatId;
        }

        // Adiciona a mensagem do usuário/admin imediatamente
        addMessageToWindow({
            sender_type: isAdmin ? 'admin' : 'user',
            text: messageText,
            sender_name: isAdmin ? document.body.dataset.userName : userName
        });

        const oldMessage = chatInput.value;
        chatInput.value = '';
        chatInput.disabled = true;
        sendButton.disabled = true;
        
        // Mostra loading apenas para usuários (resposta do bot)
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

            // Atualiza o ID do chat se for a primeira mensagem
            if (data.chat_id && !currentChatId) {
                currentChatId = data.chat_id;
                if (chatHeader) chatHeader.classList.remove('hidden');
                window.history.pushState({}, '', `/chat/${currentChatId}`);
            }

            // Adiciona a resposta
            if (data.sender_type) {
                addMessageToWindow(data);
            }
            
            // Atualiza status se necessário
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
            chatInput.value = oldMessage;
        } finally {
            if (chatStatus !== 'completed') {
                chatInput.disabled = false;
                sendButton.disabled = false;
                chatInput.focus();
            }
        }
    }

    /** Botão 'Solicitar Revisão' */
    async function handleRequestReview() {
        if (!currentChatId) return;

        reviewButton.disabled = true;
        reviewButton.textContent = 'Enviando...';

        try {
            const response = await fetch(`/api/chat/request_review/${currentChatId}`, { 
                method: 'POST' 
            });
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message);
            }

            // Adiciona mensagem de confirmação e atualiza UI
            addMessageToWindow({
                sender_type: data.sender_type,
                text: data.message
            });
            
            chatStatus = 'pending_review';
            updateChatUI();

        } catch (error) {
            alert('Erro: ' + error.message);
            reviewButton.disabled = false;
            reviewButton.textContent = 'Solicitar Revisão';
        }
    }

    /** Botão 'Desativar IA' */
    async function handleDisableIa() {
        if (!currentChatId) return;
        
        if (!confirm('Tem certeza que deseja desativar a IA para este chat? Esta ação não pode ser desfeita.')) {
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
            
            // Adiciona mensagem do sistema
            addMessageToWindow({
                sender_type: data.sender_type,
                text: data.message
            });
            
            chatStatus = 'manual_override';
            updateChatUI();

        } catch (error) {
            alert('Erro: ' + error.message);
            disableIaButton.disabled = false;
            disableIaButton.textContent = 'Desativar IA';
        }
    }

    /** Botão 'Encerrar Negociação' */
    async function handleCloseChat() {
        if (!currentChatId) return;
        
        if (!confirm('Tem certeza que deseja encerrar esta negociação? Esta ação não pode ser desfeita.')) {
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
            
            // Adiciona mensagem do sistema
            addMessageToWindow({
                sender_type: data.sender_type,
                text: data.message
            });
            
            chatStatus = 'completed';
            updateChatUI();

        } catch (error) {
            alert('Erro: ' + error.message);
            closeButton.disabled = false;
            closeButton.textContent = 'Encerrar Negociação';
        }
    }
    
    // Expõe a função de inicialização
    return {
        init: init
    };
})();