import smtplib
from email.message import EmailMessage

from flask import current_app

from app.logging_utils import log_business_event, log_dependency_call


class NotificationProviderError(Exception):
    pass


def _provider_name() -> str:
    return (current_app.config.get('AUTH_NOTIFICATION_PROVIDER') or 'smtp').strip().lower()


def _build_auth_mail(email: str, subject: str, headline: str, code: str, expires_in: int) -> EmailMessage:
    from_name = (current_app.config.get('SMTP_FROM_NAME') or 'Book Recommend').strip()
    from_email = (current_app.config.get('SMTP_FROM_EMAIL') or current_app.config.get('SMTP_USERNAME') or '').strip()
    if not from_email:
        raise NotificationProviderError('SMTP_FROM_EMAIL or SMTP_USERNAME is required')

    expires_label = f'{max(1, expires_in // 60)} 分钟' if expires_in >= 60 else f'{expires_in} 秒'
    html = f"""
    <div style="font-family: Arial, sans-serif; line-height: 1.7; color: #1f2937;">
      <h2 style="margin-bottom: 12px;">{headline}</h2>
      <p>你的验证码如下，请在 {expires_label} 内使用：</p>
      <div style="margin: 20px 0; font-size: 32px; font-weight: 700; letter-spacing: 6px; color: #2563eb;">{code}</div>
      <p>如果这不是你的操作，请忽略这封邮件。</p>
    </div>
    """
    text = f"{headline}\n\n你的验证码是：{code}\n有效期：{expires_label}。\n如果这不是你的操作，请忽略这封邮件。"

    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = f'{from_name} <{from_email}>'
    message['To'] = email
    message.set_content(text)
    message.add_alternative(html, subtype='html')
    return message


def _send_via_smtp(message: EmailMessage):
    host = (current_app.config.get('SMTP_HOST') or '').strip()
    port = int(current_app.config.get('SMTP_PORT', 465))
    username = (current_app.config.get('SMTP_USERNAME') or '').strip()
    password = (current_app.config.get('SMTP_PASSWORD') or '').strip()
    use_ssl = bool(current_app.config.get('SMTP_USE_SSL', True))
    use_tls = bool(current_app.config.get('SMTP_USE_TLS', False))

    if not host or not username or not password:
        raise NotificationProviderError('SMTP_HOST, SMTP_USERNAME and SMTP_PASSWORD are required')

    try:
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=20) as server:
                server.login(username, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=20) as server:
                server.ehlo()
                if use_tls:
                    server.starttls()
                    server.ehlo()
                server.login(username, password)
                server.send_message(message)
    except Exception as exc:
        log_dependency_call(
            current_app.logger,
            'smtp',
            'send_email',
            success=False,
            elapsed_ms=0,
            tags=['dependency', 'smtp', 'email'],
            data={'error': str(exc)},
        )
        raise NotificationProviderError(f'SMTP send failed: {exc}') from exc
    else:
        log_dependency_call(
            current_app.logger,
            'smtp',
            'send_email',
            success=True,
            elapsed_ms=0,
            tags=['dependency', 'smtp', 'email'],
            data={'to': message['To'], 'subject': message['Subject']},
        )


def send_auth_code_email(email: str, code: str, purpose: str, expires_in: int):
    provider = _provider_name()
    purpose_text = '注册验证' if purpose == 'register' else '密码重置'
    message = _build_auth_mail(
        email=email,
        subject=f'[{purpose_text}] Book Recommend 验证码',
        headline=f'用于{purpose_text}的验证码',
        code=code,
        expires_in=expires_in,
    )

    if provider == 'smtp':
        _send_via_smtp(message)
    elif provider in {'aliyun', 'aliyun_email', 'alibaba', 'tencent', 'tencent_email'}:
        raise NotificationProviderError(f'Provider "{provider}" adapter is reserved but not configured yet')
    else:
        raise NotificationProviderError(f'Unsupported notification provider: {provider}')

    log_business_event(
        current_app.logger,
        'auth.email_code_sent',
        tags=['business', 'auth', 'email'],
        data={'purpose': purpose, 'provider': provider, 'to': email},
    )
