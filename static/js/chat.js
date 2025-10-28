/* eslint-disable no-unused-vars */

const ChatModule = (function () {

    // Elementos do DOM
    let chatWindow, chatInput, sendButton, reviewButtonContainer, reviewButton;
    let closeButton, disableIaButton;
    let chatHeader, chatStatusText, inputArea;
    
    // Estado do Chat
    let currentChatId = null;
    let chatStatus = 'active';
    let reviewRequested = false; // CORREÇÃO: Flag para "botão já clicado"
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
        
        // --- Lógica do Botão de Revisão (Usuário) ---
        if (reviewButtonContainer) {
            // CORREÇÃO: Mostra se o chat está ativo, o usuário é consumidor E a revisão NUNCA foi pedida
            if (chatStatus === 'active' && userRole === 0 && !reviewRequested) {
                reviewButtonContainer.classList.remove('hidden');
            } else {
                reviewButtonContainer.classList.add('hidden');
            }
        }
        
        // --- Lógica dos Botões de Admin (Vendedor) ---
        // CORREÇÃO: Só mostra se o user for admin E o chat estiver 'assumido' ou 'manual'
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
                 // Vendedor (1) só pode fechar se o chat for dele (verificação no backend)
                 // Admin (2+) pode fechar qualquer um
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
                // Usuário não pode digitar enquanto aguarda revisão
                placeholder = 'Aguardando resposta do vendedor...';
                disabled = true;
            } else if (chatStatus === 'active' || chatStatus === 'assumed' || chatStatus === 'manual_override') {
                 placeholder = 'Digite sua mensagem...';
                 disabled = false;
            } else if (chatStatus === 'pending_review' && userRole >= 1) {
                placeholder = 'Assuma este chat para responder...';
                disabled = false; // Admin pode digitar para assumir
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

        // Mensagens do sistema (centralizadas)
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
            avatarContent = '👤'; // Avatar padrão do usuário
        } else {
            // Bot ou Admin usam o logo
            avatarContent = '<img src="/static/img/logo.png" alt="bot" style="width: 100%; height: 100%; border-radius: 50%;">';
        }

        // Define nome do remetente
        let senderName = '';
        if (msg.sender_type === 'admin') {
            senderName = `<div class="message-sender-name">${msg.sender_name || 'Vendedor'}</div>`;
        } else if (msg.sender_type === 'user') {
            senderName = `<div class="message-sender-name">${userName}</div>`;
        }
        // (Bot não tem nome)

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

    /** Mostra o "digitando..." do bot */
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

    /** Lida com o envio de mensagem (User ou Admin) */
    async function handleSendMessage() {
        const messageText = chatInput.value.trim();
        if (messageText === '' || chatInput.disabled) {
            return;
        }

        // Define o endpoint (Admin vs User)
        const isAdmin = userRole >= 1;
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
            sender_name: isAdmin ? userName : userName // Usa o nome do user logado
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
                if (chatHeader) {
                    chatHeader.classList.remove('hidden');
                    document.getElementById('chat-header-id').textContent = currentChatId;
                }
                // Atualiza a URL sem recarregar
                window.history.pushState({}, '', `/chat/${currentChatId}`);
            }

            // Adiciona a resposta (do bot ou do sistema)
            if (data.sender_type) {
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
        } finally {
            // Re-ativa a input se o chat não estiver bloqueado
            updateChatUI();
            chatInput.focus();
        }
    }

    /** Botão 'Solicitar Revisão' (Usuário) */
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

            // Adiciona mensagem de confirmação do sistema
            addMessageToWindow({
                sender_type: data.sender_type,
                text: data.message
            });
            
            // CORREÇÃO: Atualiza estado local e UI
            chatStatus = 'pending_review';
            reviewRequested = true; // Marca como clicado
            updateChatUI(); // Esconde o botão e bloqueia a input

        } catch (error) {
            alert('Erro: ' + error.message);
            reviewButton.disabled = false;
            reviewButton.textContent = 'Solicitar Revisão da Proposta';
        }
    }

    /** Botão 'Desativar IA' (Admin) */
    async function handleDisableIa() {
        if (!currentChatId) return;
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
                sender_type: data.sender_type,
                text: data.message
            });
            
            chatStatus = 'manual_override';
            updateChatUI();

        } catch (error) {
            alert('Erro: ' + error.message);
            updateChatUI(); // Re-ativa o botão se der erro
        }
    }

   /** Botão 'Encerrar Negociação' (Admin) */
    async function handleCloseChat() {
        if (!currentChatId) return;
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
                sender_type: data.sender_type,
                text: data.message
            });
            
            chatStatus = 'completed';
            updateChatUI(); // Desativa tudo

        } catch (error) {
            // CORREÇÃO: Removido o 'D' que estava sobrando.
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