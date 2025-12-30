pipeline {
    agent any

    environment {
        VENV_DIR = "venv"
        BUILD_DIR = "build"
        DEPLOY_DIR = "C:\\deploy\\flask_app"
    }

    stages {

        stage('Clone Repository') {
            steps {
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                bat """
                    python -m venv %VENV_DIR%
                    call %VENV_DIR%\\Scripts\\activate
                    pip install --upgrade pip
                    pip install -r requirements.txt
                """
            }
        }

        stage('Run Unit Tests (pytest)') {
            steps {
                bat """
                    call %VENV_DIR%\\Scripts\\activate
                    pytest
                """
            }
        }

        stage('Build Application') {
            steps {
                bat """
                    if not exist %BUILD_DIR% mkdir %BUILD_DIR%
                    xcopy app.py %BUILD_DIR% /Y
                    xcopy templates %BUILD_DIR%\\templates /E /I /Y
                    xcopy requirements.txt %BUILD_DIR% /Y
                """
            }
        }

        stage('Deploy Application') {
            steps {
                bat """
                    if not exist "%DEPLOY_DIR%" mkdir "%DEPLOY_DIR%"
                    xcopy %BUILD_DIR% "%DEPLOY_DIR%" /E /I /Y
                """
            }
        }
    }

    post {
        success {
            echo "Pipeline executed successfully"
        }
        failure {
            echo "Pipeline failed"
        }
    }
}
