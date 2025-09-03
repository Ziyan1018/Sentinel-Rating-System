import time
import hashlib
import json
import numpy as np
from collections import defaultdict
from faker import Faker
import nacl.signing
import nacl.encoding


fake = Faker()

class NostrUser:
    def __init__(self, is_malicious=False):
        # Ed25519密钥对
        self.signing_key = nacl.signing.SigningKey.generate()
        self.verify_key = self.signing_key.verify_key
        self.public_key = self.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
        self.is_malicious = is_malicious
        self.name = fake.name() if is_malicious else "Legit User"
        self.email = fake.email() if is_malicious else "user@example.com"
        
    def sign(self, content):
        event = {
            "pubkey": self.public_key,
            "created_at": int(time.time()),
            "kind": 1,  # 文本消息类型
            "tags": [],
            "content": content
        }
        
        event_serialized = json.dumps([
            0,
            event["pubkey"],
            event["created_at"],
            event["kind"],
            event["tags"],
            event["content"]
        ], separators=(',', ':'), ensure_ascii=False)
        
        event_id = hashlib.sha256(event_serialized.encode('utf-8')).hexdigest()
        
        signature = self.signing_key.sign(event_id.encode('utf-8'))
        signed_hex = signature.signature.hex()
        
        return event, signed_hex

def verify_event(event, sig):
    """验证Nostr事件签名（使用Ed25519）"""
    try:
        event_serialized = json.dumps([
            0,
            event["pubkey"],
            event["created_at"],
            event["kind"],
            event["tags"],
            event["content"]
        ], separators=(',', ':'), ensure_ascii=False)
        
        event_id = hashlib.sha256(event_serialized.encode('utf-8')).hexdigest()
        
        verify_key = nacl.signing.VerifyKey(event["pubkey"], encoder=nacl.encoding.HexEncoder)
        
        verify_key.verify(event_id.encode('utf-8'), bytes.fromhex(sig))
        return True
    except Exception as e:
        return False

def simulate_users(num_users=1000, malicious_ratio=0.2):
    """模拟用户生成内容"""
    users = []
    contents = []
    signatures = []
    labels = []
    
    for i in range(num_users):
        is_malicious = np.random.rand() < malicious_ratio
        user = NostrUser(is_malicious)
        users.append(user)
        
        
        if not is_malicious:
            content = fake.sentence()
        else:
            
            choices = np.random.choice([1, 2, 3])
            if choices == 1:
                content = f"BUY CHEAP STOCKS! {fake.uri()}"
            elif choices == 2:
                content = f"CLICK HERE FOR FREE BITCOIN: {fake.uri()}"
            else:
                content = f"URGENT: Your account will be suspended! {fake.uri()}"
        
        
        event, sig = user.sign(content)
        
        
        if user.is_malicious:
            
            attack_type = np.random.choice(['signature', 'content', 'public_key'])
            
            if attack_type == 'signature':
                
                sig = sig[:-2] + "ff"
            elif attack_type == 'content':
                
                event["content"] += " TAMPERED!"
            else:
                
                event["pubkey"] = "a1" + event["pubkey"][2:]
        
        contents.append(event)
        signatures.append(sig)
        labels.append(0 if is_malicious else 1)  
    
    return users, contents, signatures, labels

def evaluate_system(contents, signatures, labels):
    """评估验证系统性能"""
    results = defaultdict(lambda: defaultdict(int))
    verification_times = []
    
    for i, (event, sig) in enumerate(zip(contents, signatures)):
        start_time = time.perf_counter()
        is_valid = verify_event(event, sig)
        elapsed = time.perf_counter() - start_time
        verification_times.append(elapsed * 1000)  
        
        actual_label = "Malicious" if labels[i] == 0 else "Legit"
        result_key = f"{actual_label}_{'Pass' if is_valid else 'Fail'}"
        results[result_key]['count'] += 1
    
    # 计算性能指标
    tp = results['Legit_Pass']['count']
    fp = results['Malicious_Pass']['count']
    tn = results['Malicious_Fail']['count']
    fn = results['Legit_Fail']['count']
    
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total * 100 if total > 0 else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # 输出结果
    print("\n" + "="*50)
    print(f"Total Verifications: {total}")
    print(f"Avg Verification Time: {np.mean(verification_times):.4f} ms")
    print(f"Min/Max Verification Time: {np.min(verification_times):.4f}/{np.max(verification_times):.4f} ms")
    print("-"*50)
    print(f"True Positives (Legit Accepted): {tp}")
    print(f"False Positives (Malicious Accepted): {fp}")
    print(f"True Negatives (Malicious Rejected): {tn}")
    print(f"False Negatives (Legit Rejected): {fn}")
    print("-"*50)
    print(f"Accuracy: {accuracy:.2f}%")
    print(f"Precision: {precision:.2f}%")
    print(f"Recall: {recall:.2f}%")
    print(f"F1 Score: {f1_score:.2f}%")
    print("="*50)
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score,
        'avg_time': np.mean(verification_times)
    }

def generate_user_report(users, contents, signatures, labels, num_samples=5):
    """生成用户报告样本"""
    print("\n" + "="*50)
    print("User Activity Report Samples")
    print("="*50)
    
    legit_samples = [i for i, label in enumerate(labels) if label == 1][:num_samples]
    malicious_samples = [i for i, label in enumerate(labels) if label == 0][:num_samples]
    
    print("\nLegitimate User Activities:")
    for idx in legit_samples:
        user = users[idx]
        event = contents[idx]
        sig = signatures[idx]
        valid = verify_event(event, sig)
        print(f"- User: {user.name} | Key: {user.public_key[:12]}...")
        print(f"  Content: {event['content'][:60]}{'...' if len(event['content']) > 60 else ''}")
        print(f"  Signature Valid: {valid}")
        print(f"  Created At: {time.ctime(event['created_at'])}")
    
    print("\nMalicious User Activities:")
    for idx in malicious_samples:
        user = users[idx]
        event = contents[idx]
        sig = signatures[idx]
        valid = verify_event(event, sig)
        print(f"- User: {user.name} | Key: {user.public_key[:12]}...")
        print(f"  Content: {event['content'][:60]}{'...' if len(event['content']) > 60 else ''}")
        print(f"  Signature Valid: {valid}")
        print(f"  Created At: {time.ctime(event['created_at'])}")

if __name__ == "__main__":
    # （User Simulation)
    print("Simulating 2000 users (20% malicious)...")
    users, contents, signatures, labels = simulate_users(2000, 0.6)
    
    
    legit_count = sum(labels)
    malicious_count = len(labels) - legit_count
    print(f"\nSystem Summary:")
    print(f"- Total Users: {len(users)}")
    print(f"- Legitimate Users: {legit_count}")
    print(f"- Malicious Users: {malicious_count}")
    
    
    print("\nEvaluating verification system...")
    metrics = evaluate_system(contents, signatures, labels)
    
    
    generate_user_report(users, contents, signatures, labels)
    
    
    print("\nPerformance Metrics:")
    print(f"- Average Verification Time: {metrics['avg_time']:.4f} ms")
    print(f"- System Accuracy: {metrics['accuracy']:.2f}%")
    print(f"- Detection Precision: {metrics['precision']:.2f}%")
    print(f"- Attack Detection Rate: {100 - metrics['precision']:.2f}%")