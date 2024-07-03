from flask import Flask, request, render_template
from flask_socketio import SocketIO, emit
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# Database setup
engine = create_engine('sqlite:///security_monitor.db', echo=True)
Base = declarative_base()

class RequestLog(Base):
    __tablename__ = 'request_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    method = Column(String(10))
    path = Column(String(255))
    parameters = Column(Text)
    headers = Column(Text)
    payload = Column(Text)
    detected_threats = Column(Text)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# Basic rule-based threat detection
def detect_threats(request_data):
    detected_threats = []
    
    # Example rule: SQL injection detection
    sql_injection_pattern = re.compile(r'\b(union\s+select|insert\s+into|select\s+\*?\s*from)\b', re.IGNORECASE)
    if sql_injection_pattern.search(request_data['parameters'] + request_data['payload']):
        detected_threats.append("SQL Injection")

    # Add more rules for XSS, command injection, etc.

    return detected_threats

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect', namespace='/monitor')
def test_connect():
    emit('my_response', {'data': 'Connected'})

@socketio.on('monitor_request', namespace='/monitor')
def handle_monitor_request(message):
    request_data = {
        'method': message['method'],
        'path': message['path'],
        'parameters': message['parameters'],
        'headers': message['headers'],
        'payload': message['payload']
    }
    
    # Log the request
    new_request = RequestLog(
        method=request_data['method'],
        path=request_data['path'],
        parameters=request_data['parameters'],
        headers=request_data['headers'],
        payload=request_data['payload']
    )
    session.add(new_request)
    session.commit()

    # Detect threats
    detected_threats = detect_threats(request_data)

    # Update request log with detected threats
    new_request.detected_threats = ', '.join(detected_threats)
    session.commit()

    # Send real-time response to the client
    emit('monitor_response', {'data': 'Request analyzed and threats detected'}, namespace='/monitor')

if __name__ == '__main__':
    socketio.run(app, debug=True)
