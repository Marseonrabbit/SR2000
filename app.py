from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, jsonify
import os
import pandas as pd
import requests
from werkzeug.utils import secure_filename
from openpyxl import Workbook
from openpyxl.styles import Alignment, PatternFill, Font, Border, Side
from openpyxl.utils.dataframe import dataframe_to_rows
from threading import Thread, Event
import uuid

app = Flask(__name__)

# Configuration
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')  # Replace with a secure key in production

# Define upload and download folders
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
DOWNLOAD_FOLDER = os.environ.get('DOWNLOAD_FOLDER', 'downloads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

# Ensure the upload and download directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DOWNLOAD_FOLDER'], exist_ok=True)

# Global dictionary to store job details (in-memory)
jobs = {}

###############################
#       Helper Functions      #
###############################

def get_country_name(country_code):
    """Retrieve the full country name from a country code."""
    if not country_code:
        return "Unknown Country"
    try:
        response = requests.get(f"https://restcountries.com/v3.1/alpha/{country_code}")
        if response.status_code == 200:
            country_data = response.json()
            return country_data[0]["name"]["common"]
        else:
            return "Unknown Country"
    except:
        return "Unknown Country"

def classify_reputation(score):
    """Classify the IP reputation based on VirusTotal's malicious score."""
    if score == 0:
        return "Safe"
    elif 1 <= score <= 5:
        return "Neutral"
    elif score > 5:
        return "Poor"
    return "Unknown"

def get_ip_info(api_key, ip):
    """
    Fetch IP reputation information from VirusTotal.
    Returns (ISP, Country, Reputation, malicious_score_str).
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 401:
        # Invalid API key
        return None, None, None, None
    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        isp = attributes.get("as_owner", "Unknown ISP")
        country_code = attributes.get("country", "")
        country = get_country_name(country_code)

        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious_count = last_analysis_stats.get("malicious", 0)
        total_engines = sum(last_analysis_stats.values()) if last_analysis_stats else 0

        reputation = classify_reputation(malicious_count)
        if total_engines == 0:
            malicious_score_str = "0/0"
        else:
            malicious_score_str = f"{malicious_count}/{total_engines}"

        return isp, country, reputation, malicious_score_str
    else:
        return "Error", "Error", "Error", "Error"

def get_comments(api_key, resource_type, resource_id, limit=5):
    """
    Fetch top community comments from VirusTotal for a given resource.
    resource_type: 'ip_addresses' or 'files'
    """
    url = f"https://www.virustotal.com/api/v3/{resource_type}/{resource_id}/comments"
    headers = {"x-apikey": api_key}
    params = {"limit": limit}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        comments = data.get('data', [])
        top_comments = []
        for comment in comments:
            attributes = comment.get('attributes', {})
            top_comments.append({
                'user': attributes.get('user', 'Anonymous'),
                'date': attributes.get('date', ''),
                'comment': attributes.get('text', '')
            })
        return top_comments
    else:
        return []

def classify_hash_reputation(malicious_count, total_engines):
    """Classify a file hash reputation based on malicious detections."""
    if total_engines == 0:
        return "Unknown"
    malicious_percentage = (malicious_count / total_engines) * 100
    if malicious_percentage == 0:
        return "Safe"
    elif malicious_percentage <= 10:
        return "Low Risk"
    elif malicious_percentage <= 20:
        return "Moderate Risk"
    else:
        return "High Risk"

def get_hash_reputation(api_key, file_hash):
    """
    Fetch file hash reputation from VirusTotal.
    Returns (reputation, malicious_count, total_engines, file_type, malicious_score).
    """
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious_count = last_analysis_stats.get("malicious", 0)
        total_engines = sum(last_analysis_stats.values()) if last_analysis_stats else 0
        reputation = classify_hash_reputation(malicious_count, total_engines)

        file_type = attributes.get("type_description", "Unknown")

        if total_engines == 0:
            malicious_score_str = "0/0"
        else:
            malicious_score_str = f"{malicious_count}/{total_engines}"

        return (
            reputation,
            malicious_count,
            total_engines,
            file_type,
            malicious_score_str
        )
    elif response.status_code == 404:
        return "Not Found", 0, 0, "Unknown", None
    elif response.status_code == 401:
        return "Invalid API Key", 0, 0, "Unknown", None
    else:
        return "Error", 0, 0, "Unknown", None

#############################################
#         Single IP Analysis (No DL)        #
#############################################

@app.route('/')
def index():
    """Home page for single IP lookup."""
    return render_template('index.html')

@app.route('/lookup_ip', methods=['POST'])
def lookup_ip():
    """
    Handle single IP lookup in a background thread with a progress bar,
    no Excel download. The final result is displayed on screen.
    """
    ip = request.form['ip']
    api_key = session.get('api_key', '')

    if not api_key or not ip:
        flash('Please ensure API Key is saved and IP address is entered.', 'warning')
        return redirect(url_for('index'))

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        'status': 'Processing',
        'progress': 0,
        'message': f"Starting IP analysis for {ip}...",
        'cancel_event': Event(),
        'is_single_ip': True,
        'result': {}
    }

    thread = Thread(target=process_single_ip_thread, args=(job_id, ip, api_key))
    thread.start()

    return redirect(url_for('single_ip_progress', job_id=job_id))

def process_single_ip_thread(job_id, ip, api_key):
    """
    Background thread function for single IP.
    We add multiple websites to the result as placeholders.
    """
    try:
        jobs[job_id]['progress'] = 10

        isp, country, reputation, malicious_score = get_ip_info(api_key, ip)
        if isp is None:
            jobs[job_id]['status'] = 'Error'
            jobs[job_id]['message'] = 'Invalid API Key.'
            return

        # Get top 5 VT comments
        comments = get_comments(api_key, 'ip_addresses', ip, limit=5)

        # Mark partial progress
        jobs[job_id]['progress'] = 50

        # Multiple websites placeholders
        data_virustotal = {
            'title': 'www.virustotal.com',
            'details': 'Placeholder: additional VirusTotal data about IP'
        }
        data_shodan = {
            'title': 'www.shodan.io',
            'details': 'Placeholder: Shodan data about IP'
        }
        data_censys = {
            'title': 'search.censys.io',
            'details': 'Placeholder: Censys data about IP'
        }
        data_talos = {
            'title': 'talosintelligence.com',
            'details': 'Placeholder: Talos Intelligence data about IP'
        }
        data_securitytrails = {
            'title': 'securitytrails.com',
            'details': 'Placeholder: SecurityTrails data about IP'
        }
        data_ipinfo = {
            'title': 'ipinfo.io',
            'details': 'Placeholder: IPInfo data about IP'
        }
        data_greynoise = {
            'title': 'viz.greynoise.io',
            'details': 'Placeholder: GreyNoise data about IP'
        }
        data_another = {
            'title': 'another.source.com',
            'details': 'Placeholder: Another data source about IP'
        }

        # Combine them into a list
        data_sources = [
            data_virustotal,
            data_shodan,
            data_censys,
            data_talos,
            data_securitytrails,
            data_ipinfo,
            data_greynoise,
            data_another
        ]

        # Save final result
        jobs[job_id]['result'] = {
            'ip': ip,
            'isp': isp,
            'country': country,
            'reputation': reputation,
            'malicious_score': malicious_score,
            'comments': comments,
            'data_sources': data_sources
        }

        jobs[job_id]['progress'] = 100
        jobs[job_id]['status'] = 'Completed'
        jobs[job_id]['message'] = f"IP analysis completed for {ip}."

    except Exception as e:
        jobs[job_id]['status'] = 'Error'
        jobs[job_id]['message'] = f"Error processing IP {ip}: {str(e)}"

@app.route('/single_ip_progress/<job_id>')
def single_ip_progress(job_id):
    """Progress page for single IP analysis."""
    if job_id not in jobs:
        flash('Invalid job ID.', 'danger')
        return redirect(url_for('index'))
    return render_template('single_ip_progress.html', job_id=job_id)

@app.route('/single_ip/<job_id>/progress')
def get_single_ip_progress(job_id):
    """Return current progress/status for single IP analysis."""
    if job_id in jobs:
        return jsonify({
            'status': jobs[job_id]['status'],
            'progress': jobs[job_id]['progress'],
            'message': jobs[job_id]['message']
        })
    else:
        return jsonify({'status': 'Error', 'message': 'Invalid job ID.'})

@app.route('/cancel_single_ip/<job_id>', methods=['POST'])
def cancel_single_ip(job_id):
    """Cancel the single IP analysis job."""
    if job_id in jobs and jobs[job_id]['status'] == 'Processing' and jobs[job_id].get('is_single_ip'):
        jobs[job_id]['cancel_event'].set()
        jobs[job_id]['status'] = 'Canceled'
        jobs[job_id]['message'] = 'IP analysis canceled by user.'
        flash('IP analysis has been canceled.', 'info')
    else:
        flash('Cannot cancel this job.', 'warning')
    return redirect(url_for('single_ip_progress', job_id=job_id))

@app.route('/single_ip_result/<job_id>')
def single_ip_result(job_id):
    """
    Display final single IP analysis on screen once background thread is done.
    """
    if job_id not in jobs or not jobs[job_id].get('is_single_ip'):
        flash('Invalid job ID.', 'danger')
        return redirect(url_for('index'))

    if jobs[job_id]['status'] != 'Completed':
        flash('Analysis is not yet complete.', 'info')
        return redirect(url_for('single_ip_progress', job_id=job_id))

    result_data = jobs[job_id].get('result', {})
    return render_template('single_ip_result.html', result=result_data)

##################################
#      Bulk IP Lookup Routes     #
##################################

@app.route('/bulk_upload')
def bulk_upload():
    """Page for Bulk IP Lookup file upload."""
    return render_template('bulk_upload.html')

@app.route('/process_bulk_upload', methods=['POST'])
def process_bulk_upload():
    """Handle Bulk IP Lookup file upload and start analysis (Excel generated)."""
    file = request.files.get('file')
    api_key = session.get('api_key', '')

    if not api_key:
        flash('Please enter or save your VirusTotal API Key first.', 'warning')
        return redirect(url_for('bulk_upload'))

    if not file or file.filename == '':
        flash('No selected file.', 'warning')
        return redirect(url_for('bulk_upload'))

    filename = secure_filename(file.filename)
    file_ext = os.path.splitext(filename)[1].lower()

    if file_ext not in ['.csv', '.xls', '.xlsx']:
        flash('Unsupported file format. Please upload a CSV or Excel file.', 'danger')
        return redirect(url_for('bulk_upload'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    flash('File successfully uploaded. Starting analysis...', 'success')

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        'status': 'Processing',
        'progress': 0,
        'result_file': None,
        'message': 'File successfully uploaded. Starting analysis...',
        'cancel_event': Event(),
        'is_single_ip': False
    }

    thread = Thread(target=process_file_thread, args=(job_id, file_path, api_key))
    thread.start()

    return redirect(url_for('bulk_progress', job_id=job_id))

def process_file_thread(job_id, file_path, api_key):
    """Background thread to process the uploaded IP file, then generate Excel."""
    try:
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext == '.csv':
            ip_df = pd.read_csv(file_path)
        else:
            ip_df = pd.read_excel(file_path)

        # Acceptable columns
        acceptable_columns = ['ip', 'ip_address', 'ipaddress', '"source_ip"']
        columns_lower = [col.lower() for col in ip_df.columns]
        ip_column = None
        for col in acceptable_columns:
            if col.lower() in columns_lower:
                ip_column = ip_df.columns[columns_lower.index(col.lower())]
                break

        if not ip_column:
            jobs[job_id]['status'] = 'Error'
            jobs[job_id]['message'] = (
                "The uploaded file must contain a column named 'IP', 'ip_address', or 'IPAddress'."
            )
            return

        total_ips = len(ip_df)
        if total_ips == 0:
            jobs[job_id]['status'] = 'Error'
            jobs[job_id]['message'] = "The uploaded file contains no IP addresses."
            return

        output_data = []

        for idx, ip in enumerate(ip_df[ip_column]):
            if jobs[job_id]['cancel_event'].is_set():
                jobs[job_id]['status'] = 'Canceled'
                jobs[job_id]['message'] = 'IP analysis canceled by user.'
                return

            isp, country, reputation, malicious_score = get_ip_info(api_key, ip)
            if isp is None:
                jobs[job_id]['status'] = 'Error'
                jobs[job_id]['message'] = 'Invalid API Key.'
                return

            output_data.append({
                "S. No.": idx + 1,
                "IP": ip,
                "ISP": isp,
                "Country": country,
                "Reputation": reputation,
                "Malicious Score": malicious_score
            })

            jobs[job_id]['progress'] = int((idx + 1) / total_ips * 100)

        output_df = pd.DataFrame(output_data)

        # Save to Excel
        output_file = os.path.join(app.config['DOWNLOAD_FOLDER'], f'{job_id}_result.xlsx')
        wb = Workbook()
        ws = wb.active
        ws.title = "Source IP Details"

        for r_idx, row in enumerate(dataframe_to_rows(output_df, index=False, header=True), 1):
            for c_idx, value in enumerate(row, 1):
                cell = ws.cell(row=r_idx, column=c_idx, value=value)
                cell.alignment = Alignment(horizontal="center", vertical="center")
                thin_border = Border(left=Side(style="thin"), right=Side(style="thin"),
                                     top=Side(style="thin"), bottom=Side(style="thin"))
                cell.border = thin_border
                if r_idx == 1:
                    cell.fill = PatternFill(start_color="16365C", end_color="16365C", fill_type="solid")
                    cell.font = Font(color="FFFFFF", bold=True)

        # Auto-adjust columns
        for column in ws.columns:
            max_length = max(len(str(cell.value)) for cell in column if cell.value)
            adjusted_width = (max_length + 2)
            ws.column_dimensions[column[0].column_letter].width = adjusted_width

        wb.save(output_file)

        jobs[job_id]['status'] = 'Completed'
        jobs[job_id]['result_file'] = output_file
        jobs[job_id]['message'] = 'IP analysis completed successfully.'
    except Exception as e:
        jobs[job_id]['status'] = 'Error'
        jobs[job_id]['message'] = f'Error processing file: {str(e)}'
    finally:
        # Remove the uploaded file
        if os.path.exists(file_path):
            os.remove(file_path)

@app.route('/bulk_progress/<job_id>')
def bulk_progress(job_id):
    """Progress page for the bulk IP analysis."""
    if job_id not in jobs:
        flash('Invalid job ID.', 'danger')
        return redirect(url_for('bulk_upload'))
    return render_template('bulk_lookup_progress.html', job_id=job_id)

@app.route('/progress/<job_id>')
def get_progress(job_id):
    """Return current progress/status for any job (bulk IP, bulk hash)."""
    if job_id in jobs:
        return jsonify({
            'status': jobs[job_id]['status'],
            'progress': jobs[job_id]['progress'],
            'message': jobs[job_id]['message']
        })
    else:
        return jsonify({'status': 'Error', 'message': 'Invalid job ID.'})

@app.route('/download/<job_id>')
def download_result(job_id):
    """Download IP or Hash analysis result (bulk only)."""
    if job_id in jobs and jobs[job_id]['status'] == 'Completed':
        return send_file(jobs[job_id]['result_file'], as_attachment=True)
    else:
        flash('Result file not available.', 'warning')
        return redirect(url_for('bulk_upload'))

@app.route('/cancel/<job_id>', methods=['POST'])
def cancel_job(job_id):
    """Cancel a bulk IP or bulk hash analysis job."""
    if job_id in jobs and jobs[job_id]['status'] == 'Processing' and not jobs[job_id].get('is_single_ip'):
        jobs[job_id]['cancel_event'].set()
        jobs[job_id]['status'] = 'Canceled'
        jobs[job_id]['message'] = 'Analysis canceled by user.'
        flash('Analysis has been canceled.', 'info')
    else:
        flash('Cannot cancel this job.', 'warning')
    return redirect(url_for('bulk_progress', job_id=job_id))

#######################################
#   Bulk Hash Analysis (Modified)     #
#######################################

@app.route('/bulk_hash_upload')
def bulk_hash_upload():
    """Page for Bulk Hash Lookup file upload."""
    return render_template('bulk_hash_upload.html')

@app.route('/process_bulk_hash_upload', methods=['POST'])
def process_bulk_hash_upload():
    """Handle Bulk Hash Lookup file upload and start analysis."""
    file = request.files.get('file')
    api_key = session.get('api_key', '')

    if not api_key:
        flash('Please enter or save your VirusTotal API Key first.', 'warning')
        return redirect(url_for('bulk_hash_upload'))

    if not file or file.filename == '':
        flash('No selected file.', 'warning')
        return redirect(url_for('bulk_hash_upload'))

    filename = secure_filename(file.filename)
    file_ext = os.path.splitext(filename)[1].lower()

    if file_ext not in ['.csv', '.xls', '.xlsx']:
        flash('Unsupported file format. Please upload a CSV or Excel file.', 'danger')
        return redirect(url_for('bulk_hash_upload'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    flash('File successfully uploaded. Starting hash analysis...', 'success')

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        'status': 'Processing',
        'progress': 0,
        'result_file': None,
        'message': 'File successfully uploaded. Starting analysis...',
        'cancel_event': Event(),
        'is_single_ip': False
    }

    thread = Thread(target=process_hash_file_thread, args=(job_id, file_path, api_key))
    thread.start()

    return redirect(url_for('bulk_hash_progress', job_id=job_id))

def process_hash_file_thread(job_id, file_path, api_key):
    """
    Background thread to process a file of hashes, produce Excel output.
    We have removed malicious count, total engines, and file names from the final output.
    """
    try:
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext == '.csv':
            hash_df = pd.read_csv(file_path)
        else:
            hash_df = pd.read_excel(file_path)

        # Acceptable hash columns
        acceptable_columns = ['hash', 'file_hash', 'sha256', 'md5', 'sha1']
        columns_lower = [col.lower() for col in hash_df.columns]
        hash_column = None
        for col in acceptable_columns:
            if col.lower() in columns_lower:
                hash_column = hash_df.columns[columns_lower.index(col.lower())]
                break

        if not hash_column:
            jobs[job_id]['status'] = 'Error'
            jobs[job_id]['message'] = (
                "The uploaded file must contain a column named 'hash', 'file_hash', 'sha256', 'md5', or 'sha1'."
            )
            return

        total_hashes = len(hash_df)
        if total_hashes == 0:
            jobs[job_id]['status'] = 'Error'
            jobs[job_id]['message'] = "The uploaded file contains no hashes."
            return

        output_data = []

        for idx, file_hash in enumerate(hash_df[hash_column]):
            if jobs[job_id]['cancel_event'].is_set():
                jobs[job_id]['status'] = 'Canceled'
                jobs[job_id]['message'] = 'Hash analysis canceled by user.'
                return

            # Now get the minimal data for each hash
            (
                reputation,
                malicious_count,
                total_engines,
                file_type,
                malicious_score
            ) = get_hash_reputation(api_key, file_hash)

            if reputation == "Invalid API Key":
                jobs[job_id]['status'] = 'Error'
                jobs[job_id]['message'] = 'Invalid API Key.'
                return

            # We do NOT include malicious_count, total_engines, or file names in the final output
            output_data.append({
                "S. No.": idx + 1,
                "File Hash": file_hash,
                "Reputation": reputation,
                "File Type": file_type,
                "Malicious Score": malicious_score
            })

            jobs[job_id]['progress'] = int((idx + 1) / total_hashes * 100)

        output_df = pd.DataFrame(output_data)

        output_file = os.path.join(app.config['DOWNLOAD_FOLDER'], f'{job_id}_hash_result.xlsx')
        wb = Workbook()
        ws = wb.active
        ws.title = "Hash Details"

        for r_idx, row in enumerate(dataframe_to_rows(output_df, index=False, header=True), 1):
            for c_idx, value in enumerate(row, 1):
                cell = ws.cell(row=r_idx, column=c_idx, value=value)
                cell.alignment = Alignment(horizontal="center", vertical="center")
                thin_border = Border(left=Side(style="thin"), right=Side(style="thin"),
                                     top=Side(style="thin"), bottom=Side(style="thin"))
                cell.border = thin_border
                if r_idx == 1:
                    cell.fill = PatternFill(start_color="16365C", end_color="16365C", fill_type="solid")
                    cell.font = Font(color="FFFFFF", bold=True)

        # Auto-adjust columns
        for column in ws.columns:
            max_length = max(len(str(cell.value)) for cell in column if cell.value)
            adjusted_width = (max_length + 2)
            ws.column_dimensions[column[0].column_letter].width = adjusted_width

        wb.save(output_file)

        jobs[job_id]['status'] = 'Completed'
        jobs[job_id]['result_file'] = output_file
        jobs[job_id]['message'] = 'Hash analysis completed successfully.'
    except Exception as e:
        jobs[job_id]['status'] = 'Error'
        jobs[job_id]['message'] = f'Error processing file: {str(e)}'
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

@app.route('/bulk_hash_progress/<job_id>')
def bulk_hash_progress(job_id):
    """Progress page for bulk hash analysis."""
    if job_id not in jobs:
        flash('Invalid job ID.', 'danger')
        return redirect(url_for('bulk_hash_upload'))
    return render_template('bulk_hash_progress.html', job_id=job_id)

###############################
#     Single Hash Lookup      #
###############################

@app.route('/hash_lookup')
def hash_lookup():
    """Page for single hash lookup."""
    return render_template('hash_lookup.html')

@app.route('/lookup_hash', methods=['POST'])
def lookup_hash():
    """
    Handle single hash reputation check.
    (We haven't removed malicious_count / total_engines for single-hash display,
     only for the bulk output.)
    """
    file_hash = request.form['file_hash']
    api_key = session.get('api_key', '')

    if not api_key or not file_hash:
        flash('Please ensure API Key is saved and File Hash is entered.', 'warning')
        return redirect(url_for('hash_lookup'))

    (
        reputation,
        malicious_count,
        total_engines,
        file_type,
        malicious_score
    ) = get_hash_reputation(api_key, file_hash)

    if reputation == "Unknown":
        flash('Unable to retrieve hash reputation.', 'warning')
        return redirect(url_for('hash_lookup'))
    elif reputation == "Not Found":
        flash('File hash not found in VirusTotal database.', 'info')
        return redirect(url_for('hash_lookup'))
    elif reputation == "Invalid API Key":
        flash('Invalid API Key.', 'danger')
        return redirect(url_for('hash_lookup'))
    elif reputation == "Error":
        flash('An error occurred while retrieving data.', 'danger')
        return redirect(url_for('hash_lookup'))

    comments = get_comments(api_key, 'files', file_hash, limit=5)

    result_data = {
        'file_hash': file_hash,
        'reputation': reputation,
        'malicious_count': malicious_count,
        'total_engines': total_engines,
        'file_type': file_type,
        'malicious_score': malicious_score,
        'comments': comments
    }

    return render_template('hash_result.html', result=result_data)

################################
#       API Key Management     #
################################

@app.route('/api_key')
def api_key_page():
    """Page for API Key Management."""
    return render_template('api_key.html')

@app.route('/save_api_key', methods=['POST'])
def save_api_key_route():
    """Save the API Key to the session."""
    api_key = request.form.get('api_key')
    if not api_key:
        flash('Please enter an API Key before saving.', 'warning')
        return redirect(url_for('api_key_page'))

    session['api_key'] = api_key
    flash('API Key saved successfully.', 'success')
    return redirect(url_for('api_key_page'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)