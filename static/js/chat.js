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
    let isAdminViewingOthersChat = false; // Adicionado para lógica de botões

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
        isAdminViewingOthersChat = config.isAdminViewingOthersChat || false; // Recebe do backend

        // --- Adicionar mapeamento para botões WebRTC ---
        const audioCallButton = document.getElementById('start-audio-call-button');
        const videoCallButton = document.getElementById('start-video-call-button');
        const screenShareButton = document.getElementById('start-screen-share-button');


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

         // --- Adicionar listeners para botões WebRTC ---
        if (audioCallButton) {
            audioCallButton.addEventListener('click', () => {
                alert('Placeholder: Iniciar chamada de áudio...');
                // A lógica WebRTC começaria aqui
            });
        }
        if (videoCallButton) {
            videoCallButton.addEventListener('click', () => {
                alert('Placeholder: Iniciar chamada de vídeo...');
                // A lógica WebRTC começaria aqui
            });
        }
         if (screenShareButton) {
            screenShareButton.addEventListener('click', () => {
                alert('Placeholder: Iniciar partilha de ecrã...');
                // A lógica WebRTC começaria aqui
            });
        }


        scrollToBottom();
        updateChatUI(); // Já atualiza a visibilidade dos botões admin
    }

     /** Auto-resize textarea */
    function autoResizeTextarea(textarea) {
        if (!textarea) return; // Verifica se o elemento existe
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

        // --- Lógica dos Botões de Admin ---
        // Botões só aparecem se for admin E estiver a ver chat de OUTRO ou um chat ASSUMIDO por si
        const showAdminButtons = userRole >= 1 && isAdminViewingOthersChat && chatStatus !== 'completed';

        if (disableIaButton) {
            if (showAdminButtons && (chatStatus === 'assumed' || chatStatus === 'manual_override')) { // Só mostra se assumido ou manual
                disableIaButton.classList.remove('hidden');
                disableIaButton.textContent = chatStatus === 'manual_override' ? 'IA Desativada' : 'Desativar IA';
                disableIaButton.disabled = chatStatus === 'manual_override';
            } else {
                disableIaButton.classList.add('hidden');
            }
        }

        if (closeButton) {
            // Mostra se for admin e o chat não estiver completo E estiver a ver chat de outro/assumido
            if (showAdminButtons) { // A condição showAdminButtons já inclui userRole >= 1 e isAdminViewingOthersChat e !completed
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
            } else if (chatStatus === 'pending_review' && userRole >= 1 && isAdminViewingOthersChat) { // Admin vendo chat pendente de outro
                 placeholder = 'Responda para assumir este atendimento...';
                 disabled = false;
             } else if (chatStatus === 'pending_review' && userRole >= 1 && !isAdminViewingOthersChat) { // Admin vendo SEU chat pendente (não deveria acontecer, mas por segurança)
                 placeholder = 'Aguardando revisão...';
                 disabled = true;
            } else if (chatStatus === 'active' || chatStatus === 'assumed' || chatStatus === 'manual_override') {
                 placeholder = 'Digite sua mensagem...';
                 disabled = false;
            }

            chatInput.disabled = disabled;
            chatInput.placeholder = placeholder;
            if (sendButton) { // Verifica se sendButton existe
                 sendButton.disabled = disabled;
            }
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

        // Define nome do remetente
        let senderName = '';
        if (msg.sender_type === 'admin') {
            senderName = `<div class="message-sender-name">${msg.sender_name || 'Vendedor'}</div>`;
        } else if (msg.sender_type === 'user') {
            // Usa o nome do utilizador logado (userName) se for ele a enviar,
            // ou o nome passado na mensagem (se vier do histórico, por ex.)
             senderName = `<div class="message-sender-name">${msg.sender_name || userName}</div>`;
        }

        // HTML SEM O AVATAR
        container.innerHTML = `
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
        if (!chatWindow) return; // Adiciona verificação
        removeLoadingBubble(); // Garante que só haja um
        const isScrolledToBottom = chatWindow.scrollHeight - chatWindow.clientHeight <= chatWindow.scrollTop + 1;

        const container = document.createElement('div');
        container.classList.add('message-container', 'bot', 'loading-bubble');
        
        // HTML SEM O AVATAR
        container.innerHTML = `
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
         if (!chatWindow) return; // Adiciona verificação
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
        if (!chatInput || !sendButton) return; // Garante que elementos existem

        const messageText = chatInput.value.trim();
        // Limpa o input IMEDIATAMENTE após pegar o valor
        chatInput.value = '';
        autoResizeTextarea(chatInput); // Ajusta a altura após limpar

        // Verifica se a mensagem está vazia DEPOIS de limpar (se estava desabilitado, não faz nada)
        if (messageText === '' || chatInput.disabled) {
            // Se estava vazio ou desabilitado, não envia nada.
             // Auto-resize já foi chamado, então a altura está correta.
            return;
        }

        // Determina se a mensagem é enviada como 'admin' ou 'user'
        // Regra: Envia como 'admin' APENAS se for admin E estiver a ver o chat de outro utilizador
        const senderType = (userRole >= 1 && isAdminViewingOthersChat) ? 'admin' : 'user';

        // Determina o URL da API correta
        const url = senderType === 'admin'
            ? `/api/chat/admin_message/${currentChatId}` // Usa a API admin se for admin a responder a outro
            : '/api/chat/user_message'; // Usa a API user se for utilizador normal ou admin no seu próprio chat

        const body = { message: messageText };
        // Adiciona chat_id se já existir (para user_message)
        if (senderType === 'user' && currentChatId) {
            body.chat_id = currentChatId;
        }

        // Adiciona a mensagem à janela imediatamente com o tipo correto
        addMessageToWindow({
            sender_type: senderType,
            text: messageText,
            sender_name: userName // Nome do utilizador logado
        });

        // Desabilita input e botão enquanto espera a resposta
        chatInput.disabled = true;
        sendButton.disabled = true;

        // Mostra loading apenas se a IA for responder (não é admin a enviar)
        if (senderType === 'user') {
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
                 // Tenta mostrar a mensagem de erro do backend
                throw new Error(data.message || `Erro ${response.status}`);
            }

            // Remove loading APENAS se foi mostrado
             if (senderType === 'user') {
                removeLoadingBubble();
            }


            // Atualiza o ID do chat se for a primeira mensagem (retorno do backend)
             // Isso acontece principalmente na api_chat_user_message
            if (data.chat_id && !currentChatId && senderType === 'user') {
                currentChatId = data.chat_id;
                // Atualiza a URL sem recarregar a página
                window.history.pushState({ chatId: currentChatId }, '', `/chat/${currentChatId}`);
                 // Atualiza o cabeçalho se ele existir
                if (chatHeader) {
                    chatHeader.classList.remove('hidden');
                     const headerIdElement = document.getElementById('chat-header-id');
                     if (headerIdElement) {
                         headerIdElement.textContent = currentChatId;
                     }
                }
                 // É importante re-inicializar isAdminViewingOthersChat ou recarregar
                 // para que os botões admin apareçam corretamente se necessário
                 // (embora neste fluxo não devam aparecer logo após criar o chat)
                 // Poderia forçar um reload ou re-init:
                 // window.location.reload(); // Simples mas recarrega tudo
                 // Ou re-init com novos dados, se a API retornasse tudo necessário
            }


            // Adiciona a resposta (do bot/sistema OU a confirmação da msg admin)
            // Evita adicionar a própria mensagem enviada novamente
            if (data.sender_type && data.sender_type !== senderType) {
                addMessageToWindow(data);
            } else if (senderType === 'admin' && data.success) {
                 // Se foi admin a enviar e a API confirmou sucesso,
                 // pode querer adicionar uma pequena confirmação visual ou log,
                 // mas a mensagem já está na janela.
                 console.log("Mensagem de admin enviada com sucesso.");
            }


            // Atualiza status se o backend enviar um novo
            if (data.chat_status) {
                chatStatus = data.chat_status;
                 // Se o admin acabou de assumir, atualiza a flag para mostrar botões
                 if (chatStatus === 'assumed' && userRole >= 1) {
                     isAdminViewingOthersChat = true; // Agora está a ver um chat assumido
                 }
                updateChatUI();
            }

        } catch (error) {
            console.error('Erro ao enviar mensagem:', error);
            // Remove loading se existir
             if (senderType === 'user') {
                 removeLoadingBubble();
             }
            addMessageToWindow({
                sender_type: 'system',
                text: `Erro ao enviar: ${error.message}. Tente novamente.` // Mostra erro
            });
            // Não restaura a mensagem, pois o utilizador pode querer tentar enviar de novo
        } finally {
            // Re-ativa a input se o chat não estiver bloqueado/terminado
             updateChatUI(); // Chama para garantir que o estado (disabled/placeholder) está correto
             if (!chatInput.disabled) {
                 chatInput.focus(); // Foca no input se ele estiver ativo
             }
        }
    }

    /** Botão 'Solicitar Revisão' (Usuário) */
    async function handleRequestReview() {
        if (!currentChatId || !reviewButton || reviewButton.disabled) return; // Verifica reviewButton

        reviewButton.disabled = true;
        reviewButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enviando...';

        try {
            const response = await fetch(`/api/chat/request_review/${currentChatId}`, {
                method: 'POST'
            });
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || `Erro ${response.status}`);
            }

            addMessageToWindow({
                sender_type: data.sender_type || 'system', // Garante que é system
                text: data.message
            });

            chatStatus = 'pending_review';
            reviewRequested = true; // Marca como clicado
            updateChatUI(); // Esconde botão, bloqueia input do user

        } catch (error) {
            alert('Erro ao solicitar revisão: ' + error.message);
            // Reabilita o botão apenas se o erro ocorreu
            reviewButton.disabled = false;
            reviewButton.innerHTML = '<i class="fas fa-gavel"></i> Solicitar Revisão da Proposta';
        }
    }

    /** Botão 'Desativar IA' (Admin) */
    async function handleDisableIa() {
         if (!currentChatId || !disableIaButton || disableIaButton.disabled) return; // Verifica disableIaButton
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
                 throw new Error(data.message || `Erro ${response.status}`);
            }

            addMessageToWindow({
                sender_type: data.sender_type || 'system',
                text: data.message
            });

            chatStatus = 'manual_override';
            updateChatUI(); // Atualiza texto e estado do botão

        } catch (error) {
            alert('Erro ao desativar IA: ' + error.message);
            updateChatUI(); // Re-habilita com texto correto se der erro
        }
    }

   /** Botão 'Encerrar Negociação' (Admin) */
    async function handleCloseChat() {
         if (!currentChatId || !closeButton || closeButton.disabled) return; // Verifica closeButton
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
                 throw new Error(data.message || `Erro ${response.status}`);
            }

            addMessageToWindow({
                sender_type: data.sender_type || 'system',
                text: data.message
            });

            chatStatus = 'completed';
            updateChatUI(); // Desativa input e botões

        } catch (error) {
            alert('Erro ao encerrar negociação: ' + error.message); // Corrigido
            // Não reabilita o botão se der erro, pois o estado pode ser inconsistente
             closeButton.textContent = 'Erro'; // Indica erro no botão
             // updateChatUI(); // Atualiza UI para refletir estado atual (pode ainda estar ativo no backend)
        }
    }

    // Expõe a função de inicialização
    return {
        init: init
    };
})();