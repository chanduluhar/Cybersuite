import io
import mimetypes
import re
from pathlib import Path
from flask import Blueprint, render_template, request, send_file, flash, redirect, url_for, current_app, session
from flask import Blueprint, render_template, request, send_file, flash, redirect, url_for, current_app, session
from flask_login import login_required, current_user
from models.file import FileMetadata
from models.audit_log import AuditLog
from models.user import User
from models.shared_file import SharedFile
from utils.file_handler import FileHandler
from extensions import db
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

crypto_bp = Blueprint('crypto', __name__, url_prefix='/crypto')

SUPPORTED_ALGORITHM_MODES = {
    'AES': ['CBC', 'GCM', 'CTR', 'CFB', 'OFB'],
    'CHACHA20': ['POLY1305'],
    'BLOWFISH': ['CBC'],
    '3DES': ['CBC'],
    'DES': ['CBC']
}

SUPPORTED_KEY_SIZES = {
    'AES': [128, 192, 256],
    'CHACHA20': [256],
    'BLOWFISH': [128, 192, 256, 448],
    '3DES': [128, 192],
    'DES': [56]
}


def _read_decryption_key():
    return (request.form.get('decryption_key') or '').strip()


def _extract_file_id_from_download_name(filename: str):
    match = re.search(r'_encrypted_(\d+)(?=\.[^.]+$)|_encrypted_(\d+)$', filename or '', re.IGNORECASE)
    if not match:
        return None
    file_id_text = match.group(1) or match.group(2)
    try:
        return int(file_id_text)
    except (TypeError, ValueError):
        return None


def _resolve_uploaded_file_metadata(uploaded_name: str, uploaded_bytes: bytes):
    normalized_name = os.path.basename((uploaded_name or '').strip())
    user_files = FileMetadata.query.filter_by(user_id=current_user.id).all()
    if not user_files:
        return None

    # 1) Preferred path: download filename contains file_id (e.g. *_encrypted_42.ext)
    hinted_id = _extract_file_id_from_download_name(normalized_name)
    if hinted_id:
        hinted = next((f for f in user_files if f.id == hinted_id), None)
        if hinted:
            return hinted

    # 2) Direct vault filename upload (e.g. randomhex.enc)
    exact = next((f for f in user_files if (f.encrypted_filename or '').lower() == normalized_name.lower()), None)
    if exact:
        return exact

    # 3) Legacy/new download naming patterns without guaranteed uniqueness
    named_matches = []
    for file_metadata in user_files:
        stem = Path(file_metadata.original_filename).stem
        suffix = Path(file_metadata.original_filename).suffix
        legacy_name = f'{stem}_encrypted{suffix}'.lower()
        tagged_name = f'{stem}_encrypted_{file_metadata.id}{suffix}'.lower()
        if normalized_name.lower() in (legacy_name, tagged_name):
            named_matches.append(file_metadata)

    if len(named_matches) == 1:
        return named_matches[0]

    # 4) Final fallback: compare ciphertext bytes against vault records (size-filtered)
    upload_folder = current_app.config['UPLOAD_FOLDER']
    target_size = len(uploaded_bytes or b'')
    for file_metadata in user_files:
        vault_path = os.path.join(upload_folder, file_metadata.encrypted_filename)
        if not os.path.exists(vault_path):
            continue
        try:
            if os.path.getsize(vault_path) != target_size:
                continue
            with open(vault_path, 'rb') as vault_file:
                if vault_file.read() == uploaded_bytes:
                    return file_metadata
        except OSError:
            continue

    return None


@crypto_bp.route('/')
@crypto_bp.route('/vault')
@login_required
def vault_home():
    return render_template('crypto/vault.html')


@crypto_bp.route('/dashboard')
@login_required
def dashboard():
    files = FileMetadata.query.filter_by(user_id=current_user.id).order_by(FileMetadata.created_at.desc()).all()
    return render_template('crypto/dashboard.html', files=files)


@crypto_bp.route('/encrypt', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        algorithm = (request.form.get('algorithm', 'AES') or 'AES').upper()
        mode = (request.form.get('mode', 'CBC') or 'CBC').upper()
        try:
            key_size = int(request.form.get('key_size', 256))
        except (TypeError, ValueError):
            key_size = 256

        if algorithm not in SUPPORTED_KEY_SIZES:
            flash('Unsupported encryption algorithm selected', 'danger')
            return redirect(request.url)

        allowed_modes = SUPPORTED_ALGORITHM_MODES.get(algorithm, ['CBC'])
        if mode not in allowed_modes:
            mode = allowed_modes[0]
            flash(f'Cipher mode was adjusted to {mode} for {algorithm}.', 'warning')

        allowed_key_sizes = SUPPORTED_KEY_SIZES[algorithm]
        if key_size not in allowed_key_sizes:
            key_size = max(allowed_key_sizes)
            flash(f'Key size was adjusted to {key_size}-bit for {algorithm}.', 'warning')

        try:
            metadata, generated_decryption_key = FileHandler.encrypt_and_save(file, current_user, algorithm, mode, key_size)
            session[f'generated_decryption_key_{metadata.id}'] = generated_decryption_key
            return redirect(url_for('crypto.result_page', operation='encryption', file_id=metadata.id))
        except Exception as e:
            flash(f'Error during encryption: {str(e)}', 'danger')

    files = FileMetadata.query.filter_by(user_id=current_user.id).order_by(FileMetadata.created_at.desc()).all()
    return render_template('crypto/encrypt.html', files=files)


@crypto_bp.route('/decrypt')
@login_required
def decrypt_page():
    files = FileMetadata.query.filter_by(user_id=current_user.id) \
        .order_by(FileMetadata.created_at.desc()).all()
    return render_template('crypto/decrypt.html', files=files)


@crypto_bp.route('/decrypt/upload', methods=['POST'])
@login_required
def decrypt_upload():
    if 'file' not in request.files:
        flash('Please select an encrypted file first.', 'danger')
        return redirect(url_for('crypto.decrypt_page'))

    uploaded_file = request.files['file']
    if not uploaded_file or uploaded_file.filename == '':
        flash('Please select an encrypted file first.', 'danger')
        return redirect(url_for('crypto.decrypt_page'))

    decryption_key = _read_decryption_key()
    if not decryption_key:
        flash('Please enter the decryption key.', 'danger')
        return redirect(url_for('crypto.decrypt_page'))

    ciphertext = uploaded_file.read()
    if not ciphertext:
        flash('Uploaded file is empty or unreadable.', 'danger')
        return redirect(url_for('crypto.decrypt_page'))

    file_metadata = _resolve_uploaded_file_metadata(uploaded_file.filename, ciphertext)
    if not file_metadata:
        flash('Uploaded encrypted file was not found in your vault records.', 'danger')
        return redirect(url_for('crypto.decrypt_page'))

    try:
        # Validate key + ciphertext first, then follow result-page flow (no direct download).
        FileHandler.decrypt_ciphertext(
            ciphertext,
            file_metadata,
            current_user,
            decryption_key=decryption_key,
            log_action=False
        )
        session[f'decryption_key_{file_metadata.id}'] = decryption_key
        return redirect(url_for('crypto.result_page', operation='decryption', file_id=file_metadata.id))
    except Exception as e:
        flash(f'Invalid decryption key or error: {str(e)}', 'danger')
        return redirect(url_for('crypto.decrypt_page'))


@crypto_bp.route('/decrypt/process/<int:file_id>', methods=['POST'])
@login_required
def process_decryption(file_id):
    file_metadata = FileMetadata.query.get_or_404(file_id)
    decryption_key = _read_decryption_key()

    if file_metadata.user_id != current_user.id and not decryption_key:
        flash('A decryption key is required to access files that are not yours.', 'danger')
        return redirect(url_for('crypto.decrypt_page'))

    if file_metadata.decryption_key_hash and not decryption_key:
        flash('Decryption key is required for this file.', 'danger')
        return redirect(url_for('crypto.decrypt_page'))

    try:
        FileHandler.decrypt_and_get(file_metadata, current_user, decryption_key=decryption_key or None, log_action=False)
        session[f'decryption_key_{file_metadata.id}'] = decryption_key
        return redirect(url_for('crypto.result_page', operation='decryption', file_id=file_metadata.id))
    except Exception as e:
        flash(f'Invalid decryption key or error: {str(e)}', 'danger')
        return redirect(url_for('crypto.decrypt_page'))


@crypto_bp.route('/result/<string:operation>/<int:file_id>')
@login_required
def result_page(operation, file_id):
    operation = operation.lower()
    if operation not in ('encryption', 'decryption'):
        flash('Invalid operation type', 'danger')
        return redirect(url_for('crypto.upload'))

    file_metadata = FileMetadata.query.get_or_404(file_id)
    generated_decryption_key = None
    if operation == 'encryption':
        generated_decryption_key = session.pop(f'generated_decryption_key_{file_id}', None)

    return render_template('crypto/result.html', operation=operation,
                           file=file_metadata, generated_decryption_key=generated_decryption_key)


@crypto_bp.route('/download-encrypted/<int:file_id>')
@login_required
def download_encrypted(file_id):
    file_metadata = FileMetadata.query.get_or_404(file_id)
    if file_metadata.user_id != current_user.id:
        flash('Permission denied', 'danger')
        return redirect(url_for('crypto.upload'))

    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], file_metadata.encrypted_filename)
    if not os.path.exists(filepath):
        flash('Encrypted file not found on disk', 'danger')
        return redirect(url_for('crypto.upload'))

    return send_file(filepath, as_attachment=True,
                     download_name=f"{Path(file_metadata.original_filename).stem}_encrypted_{file_metadata.id}{Path(file_metadata.original_filename).suffix}",
                     mimetype='application/octet-stream')


@crypto_bp.route('/download/<int:file_id>', methods=['GET', 'POST'])
@login_required
def download_decrypted(file_id):
    file_metadata = FileMetadata.query.get_or_404(file_id)
    decryption_key = ''
    if request.method == 'POST':
        decryption_key = _read_decryption_key()
    else:
        decryption_key = (request.args.get('decryption_key') or '').strip()
        if not decryption_key:
            decryption_key = session.pop(f'decryption_key_{file_metadata.id}', '')

    if file_metadata.decryption_key_hash and not decryption_key:
        flash('Decryption key is required to download this file.', 'danger')
        return redirect(url_for('crypto.decrypt_page'))

    try:
        decrypted_data = FileHandler.decrypt_and_get(file_metadata, current_user, decryption_key=decryption_key or None)
        mimetype = mimetypes.guess_type(file_metadata.original_filename)[0] or 'application/octet-stream'
        return send_file(io.BytesIO(decrypted_data), as_attachment=True,
                         download_name=file_metadata.original_filename, mimetype=mimetype)
    except Exception as e:
        flash(f'Error during decryption: {str(e)}', 'danger')
        return redirect(url_for('crypto.decrypt_page'))


@crypto_bp.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete(file_id):
    file_metadata = FileMetadata.query.get_or_404(file_id)
    if file_metadata.user_id != current_user.id:
        flash('Permission denied', 'danger')
        return redirect(url_for('crypto.decrypt_page'))

    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], file_metadata.encrypted_filename)
    if os.path.exists(filepath):
        os.remove(filepath)

    db.session.delete(file_metadata)
    db.session.commit()
    flash('File deleted successfully', 'success')
    return redirect(url_for('crypto.decrypt_page'))


@crypto_bp.route('/share/<int:file_id>', methods=['POST'])
@login_required
def share_file(file_id):
    file_metadata = FileMetadata.query.get_or_404(file_id)
    if file_metadata.user_id != current_user.id:
        flash('You can only share your own files.', 'danger')
        return redirect(url_for('crypto.dashboard'))

    recipient_email = (request.form.get('recipient_email') or '').strip().lower()
    if not recipient_email:
        flash('Please enter a valid email address.', 'danger')
        return redirect(url_for('crypto.dashboard'))

    if recipient_email == current_user.email.lower():
        flash('You cannot share a file with yourself.', 'warning')
        return redirect(url_for('crypto.dashboard'))

    existing = SharedFile.query.filter_by(file_id=file_id, shared_with_email=recipient_email).first()
    if existing:
        flash(f'File is already shared with {recipient_email}.', 'info')
        return redirect(url_for('crypto.dashboard'))

    share = SharedFile(file_id=file_id, shared_by=current_user.id,
                       shared_with_email=recipient_email, is_one_time=False)
    db.session.add(share)
    db.session.commit()
    flash(f'File successfully shared with {recipient_email}!', 'success')
    return redirect(url_for('crypto.dashboard'))


@crypto_bp.route('/shared')
@login_required
def shared_with_me():
    shares = db.session.query(SharedFile, FileMetadata, User)         .join(FileMetadata, SharedFile.file_id == FileMetadata.id)         .join(User, SharedFile.shared_by == User.id)         .filter(SharedFile.shared_with_email == current_user.email.lower())         .order_by(SharedFile.created_at.desc())         .all()
    return render_template('crypto/shared.html', shares=shares)


@crypto_bp.route('/shared/<int:share_id>/download', methods=['POST'])
@login_required
def download_shared(share_id):
    share = SharedFile.query.get_or_404(share_id)
    if share.shared_with_email.lower() != current_user.email.lower():
        flash('Permission denied.', 'danger')
        return redirect(url_for('crypto.shared_with_me'))

    file_metadata = FileMetadata.query.get_or_404(share.file_id)
    decryption_key = _read_decryption_key()

    if not decryption_key:
        flash('Please enter the decryption key provided by the file owner.', 'danger')
        return redirect(url_for('crypto.shared_with_me'))

    try:
        decrypted_data = FileHandler.decrypt_and_get(file_metadata, current_user,
                                                      decryption_key=decryption_key, log_action=True)
    except Exception as e:
        flash(f'Decryption failed: {e}', 'danger')
        return redirect(url_for('crypto.shared_with_me'))

    mimetype = mimetypes.guess_type(file_metadata.original_filename)[0] or 'application/octet-stream'
    return send_file(io.BytesIO(decrypted_data), as_attachment=True,
                     download_name=file_metadata.original_filename, mimetype=mimetype)


# API routes for algorithm info
@crypto_bp.route('/api/algorithms')
def list_algorithms():
    from flask import jsonify
    algorithms = [
        {'name': 'AES', 'modes': ['CBC', 'GCM', 'CTR', 'CFB', 'OFB'], 'key_sizes': [128, 192, 256]},
        {'name': 'ChaCha20', 'modes': ['Poly1305'], 'key_sizes': [256]},
        {'name': 'DES', 'modes': ['CBC', 'ECB'], 'key_sizes': [56]},
        {'name': '3DES', 'modes': ['CBC', 'ECB'], 'key_sizes': [112, 168]},
        {'name': 'Blowfish', 'modes': ['CBC', 'ECB'], 'key_sizes': [128, 256, 448]}
    ]
    return jsonify(algorithms)


@crypto_bp.route('/history')
@login_required
def history():
    logs = db.session.query(AuditLog, FileMetadata.original_filename)         .outerjoin(FileMetadata, AuditLog.file_id == FileMetadata.id)         .filter(AuditLog.user_id == current_user.id)         .order_by(AuditLog.timestamp.desc())         .all()
    return render_template('crypto/history.html', logs=logs)


@crypto_bp.route('/export_history')
@login_required
def export_history():
    logs = db.session.query(AuditLog, FileMetadata.original_filename)         .outerjoin(FileMetadata, AuditLog.file_id == FileMetadata.id)         .filter(AuditLog.user_id == current_user.id)         .order_by(AuditLog.timestamp.desc())         .all()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"crypto_activity_report_{timestamp}.pdf"
    
    filepath = os.path.join(current_app.config['EXPORTS_FOLDER'], filename)

    doc = SimpleDocTemplate(filepath, pagesize=landscape(letter))
    elements = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=20, spaceAfter=20)
    normal_style = styles['Normal']
    
    elements.append(Paragraph("Encryption & Decryption Activity Report", title_style))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Paragraph(f"User: {current_user.email}", normal_style))
    elements.append(Spacer(1, 20))

    if not logs:
        elements.append(Paragraph("No activity history found.", normal_style))
        doc.build(elements)
        return send_file(filepath, as_attachment=True, download_name=filename, mimetype='application/pdf')

    # Table Header
    data = [['Action', 'File Name', 'Algorithm', 'Date', 'Time']]
    
    for log, file_name in logs:
        action = str(log.action)
        fname = str(file_name) if file_name else 'Unknown File (Deleted)'
        # Truncate very long filenames
        fname = fname[:40] + '...' if len(fname) > 40 else fname
        
        algo = str(log.algorithm_used) if log.algorithm_used else 'Unknown'
        date_str = log.timestamp.strftime('%b %d, %Y')
        time_str = log.timestamp.strftime('%H:%M:%S')
        
        data.append([action, fname, algo, date_str, time_str])

    col_widths = [80, 250, 100, 100, 100]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6366f1')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#1a1e24')),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#6366f1')),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ])
    
    for i, row in enumerate(data[1:], start=1):
        action = row[0]
        if action == 'ENCRYPT':
            style.add('TEXTCOLOR', (0, i), (0, i), colors.HexColor('#10b981')) # Success green
        elif action == 'DECRYPT':
            style.add('TEXTCOLOR', (0, i), (0, i), colors.HexColor('#6366f1')) # Primary blued
    
    table.setStyle(style)
    elements.append(table)

    doc.build(elements)
    
    return send_file(filepath, as_attachment=True, download_name=filename, mimetype='application/pdf')
