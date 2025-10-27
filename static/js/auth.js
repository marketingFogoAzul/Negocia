/* eslint-disable no-unused-vars */

// Módulo de Autenticação
const AuthModule = (function () {
    
    /**
     * Função helper para fazer chamadas de API
     * @param {string} url - O endpoint da API
     * @param {object} data - O corpo (body) da requisição
     */
    async function postData(url, data) {
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });
            
            const result = await response.json();
            result.status = response.status; // Adiciona o status code ao resultado
            return result;

        } catch (error) {
            console.error('Erro na requisição:', error);
            return { 
                success: false, 
                message: 'Erro de conexão. Tente novamente.', 
                status: 500 
            };
        }
    }

    /**
     * Mostra mensagens de erro no formulário
     * @param {string} formId - ID do formulário (ex: '#login-form')
     * @param {string} message - A mensagem de erro
     * @param {boolean} isSuccess - É uma mensagem de sucesso?
     */
    function showFormMessage(formId, message, isSuccess = false) {
        const errorElement = document.querySelector(`${formId} .error-message`);
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.color = isSuccess ? 'var(--color-success)' : 'var(--color-danger)';
            errorElement.style.display = 'block';
        }
    }

    /**
     * Controla o estado de 'loading' do botão
     * @param {string} formId - ID do formulário
     * @param {boolean} isLoading - Está carregando?
     */
    function setFormLoading(formId, isLoading) {
        const button = document.querySelector(`${formId} button[type="submit"]`);
        if (button) {
            if (isLoading) {
                button.disabled = true;
                button.textContent = 'Aguarde...';
            } else {
                button.disabled = false;
                button.textContent = (formId.includes('login')) ? 'Entrar' : 'Registrar';
            }
        }
    }

    /**
     * Inicializa o formulário de Login
     */
    function initLoginForm() {
        const form = document.getElementById('login-form');
        if (!form) return;

        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            setFormLoading('#login-form', true);
            showFormMessage('#login-form', ''); // Limpa erros antigos

            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            const result = await postData('/api/auth/login', { email, password });

            if (result.success) {
                showFormMessage('#login-form', result.message, true);
                // Sucesso! O backend cuidou da sessão, apenas redirecionamos.
                window.location.href = '/home';
            } else {
                showFormMessage('#login-form', result.message || 'Erro desconhecido.');
                setFormLoading('#login-form', false);
            }
        });
    }

    /**
     * Inicializa o formulário de Registro
     */
    function initRegisterForm() {
        const form = document.getElementById('register-form');
        if (!form) return;

        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            setFormLoading('#register-form', true);
            showFormMessage('#register-form', ''); // Limpa erros

            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm-password').value;

            if (password !== confirmPassword) {
                showFormMessage('#register-form', 'As senhas não coincidem.');
                setFormLoading('#register-form', false);
                return;
            }

            if (password.length < 6) {
                showFormMessage('#register-form', 'A senha deve ter pelo menos 6 caracteres.');
                setFormLoading('#register-form', false);
                return;
            }

            const result = await postData('/api/auth/register', { name, email, password });

            if (result.success) {
                showFormMessage('#register-form', result.message, true);
                // Sucesso! Redireciona para a home após o registro.
                setTimeout(() => {
                    window.location.href = '/home';
                }, 1000); // Espera 1s para o usuário ler a msg
            } else {
                showFormMessage('#register-form', result.message || 'Erro desconhecido.');
                setFormLoading('#register-form', false);
            }
        });
    }

    // Expõe as funções públicas
    return {
        initLoginForm: initLoginForm,
        initRegisterForm: initRegisterForm
    };

})();