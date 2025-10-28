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
        // CORREÇÃO: Usa o template de login/register que não tem .error-message
        // Vamos usar o flash message container se existir, ou alert.
        // O template de login/register que você usa (baseado em bootstrap)
        // não tem o .error-message que o style.css espera.
        // Vou usar o 'alert' por simplicidade, já que o template não tem o elemento
        if (message) {
             alert(message);
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
                button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Aguarde...';
            } else {
                const icon = (formId.includes('login')) ? 'fa-sign-in-alt' : 'fa-user-plus';
                const text = (formId.includes('login')) ? 'Entrar' : 'Criar Conta';
                button.disabled = false;
                button.innerHTML = `<i class="fas ${icon} me-2"></i>${text}`;
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

            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            const result = await postData('/api/auth/login', { email, password });

            if (result.success) {
                // CORREÇÃO: Redireciona para a URL enviada pelo backend
                window.location.href = result.redirect; 
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
                 // CORREÇÃO: Redireciona para a URL enviada pelo backend
                window.location.href = result.redirect;
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

// Inicializa os formulários se eles existirem na página
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('login-form')) {
        AuthModule.initLoginForm();
    }
    if (document.getElementById('register-form')) {
        AuthModule.initRegisterForm();
    }
});