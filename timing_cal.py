import cv2
import tkinter as tk
import time
from tkinter import filedialog, messagebox, simpledialog
import numpy as np
from PIL import Image, ImageTk
import os
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc

# Initialize pairing group for CP-ABE
group = PairingGroup('SS512')

# Placeholder for global variables
cpabe = None
pk = None
mk = None
face_regions = []
policies = [
    'attributeA',
    'attributeA',
    'attributeA'
]  # Array to store unique policies for each face
original_image = None
blurred_image = None

# New Maps to store hash values and ciphertexts
hash_map = {}
ciphertext_map = []

# Function to initialize CP-ABE scheme
def initialize_cpabe():
    global cpabe, pk, mk
    cpabe = CPabe_BSW07(group)
    (pk, mk) = cpabe.setup()

class CPabe_BSW07(ABEnc):
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj
        
        # Initialize timing accumulators and counters
        self.pairing_time = 0.0
        self.exponentiation_time = 0.0
        self.multiplication_time = 0.0
        
        self.pairing_count = 0
        self.exponentiation_count = 0
        self.multiplication_count = 0

    def setup(self):
        # Exponentiation: g = group.random(G1), gp = group.random(G2)
        start_time = time.perf_counter()
        g = group.random(G1)
        gp = group.random(G2)
        end_time = time.perf_counter()
        self.exponentiation_time += end_time - start_time
        self.exponentiation_count += 2  # Two exponentiations

        # Exponentiation: alpha, beta
        start_time = time.perf_counter()
        alpha, beta = group.random(ZR), group.random(ZR)
        end_time = time.perf_counter()
        self.exponentiation_time += end_time - start_time
        self.exponentiation_count += 2  # Two exponentiations

        # Exponentiation: h = g ** beta, f = g ** (~beta)
        start_time = time.perf_counter()
        h = g ** beta
        f = g ** (~beta)
        end_time = time.perf_counter()
        self.exponentiation_time += end_time - start_time
        self.exponentiation_count += 2  # Two exponentiations

        # Exponentiation: gp_alpha = gp ** alpha
        start_time = time.perf_counter()
        gp_alpha = gp ** alpha
        end_time = time.perf_counter()
        self.exponentiation_time += end_time - start_time
        self.exponentiation_count += 1  # One exponentiation

        # Pairing: e_gg_alpha = pair(g, gp_alpha)
        start_time = time.perf_counter()
        pairing_result = pair(g, gp_alpha)
        end_time = time.perf_counter()
        self.pairing_time += end_time - start_time
        self.pairing_count += 1  # One pairing

        pk = {'g': g, 'g2': gp, 'h': h, 'f': f, 'e_gg_alpha': pairing_result}
        mk = {'beta': beta, 'g2_alpha': gp_alpha}

        return (pk, mk)

    def keygen(self, pk, mk, S):
        # Exponentiation: r = group.random()
        start_time = time.perf_counter()
        r = group.random()
        end_time = time.perf_counter()
        self.exponentiation_time += end_time - start_time
        self.exponentiation_count += 1  # One exponentiation

        # Exponentiation: g_r = pk['g2'] ** r
        start_time = time.perf_counter()
        g_r = pk['g2'] ** r
        end_time = time.perf_counter()
        self.exponentiation_time += end_time - start_time
        self.exponentiation_count += 1  # One exponentiation

        # Multiplication: D_mult = mk['g2_alpha'] * g_r
        start_time = time.perf_counter()
        D_mult = mk['g2_alpha'] * g_r
        end_time = time.perf_counter()
        self.multiplication_time += end_time - start_time
        self.multiplication_count += 1  # One multiplication

        # Exponentiation: D = D_mult ** (1 / mk['beta'])
        start_time = time.perf_counter()
        D = D_mult ** (1 / mk['beta'])
        end_time = time.perf_counter()
        self.exponentiation_time += end_time - start_time
        self.exponentiation_count += 1  # One exponentiation

        D_j, D_j_pr = {}, {}

        for j in S:
            # Exponentiation: r_j = group.random()
            start_time = time.perf_counter()
            r_j = group.random()
            end_time = time.perf_counter()
            self.exponentiation_time += end_time - start_time
            self.exponentiation_count += 1  # One exponentiation

            # Exponentiation: hash_j = group.hash(j, G2) ** r_j
            start_time = time.perf_counter()
            hash_j = group.hash(j, G2)
            hash_j_rj = hash_j ** r_j
            end_time = time.perf_counter()
            self.exponentiation_time += end_time - start_time
            self.exponentiation_count += 1  # One exponentiation

            # Multiplication: D_j[j] = g_r * hash_j_rj
            start_time = time.perf_counter()
            D_j[j] = g_r * hash_j_rj
            end_time = time.perf_counter()
            self.multiplication_time += end_time - start_time
            self.multiplication_count += 1  # One multiplication

            # Exponentiation: D_j_pr[j] = pk['g'] ** r_j
            start_time = time.perf_counter()
            D_j_pr[j] = pk['g'] ** r_j
            end_time = time.perf_counter()
            self.exponentiation_time += end_time - start_time
            self.exponentiation_count += 1  # One exponentiation

        return {'D': D, 'Dj': D_j, 'Djp': D_j_pr, 'S': S}

    def encrypt(self, pk, M, policy_str):
        # Policy creation (Not timed)
        policy = util.createPolicy(policy_str)

        # Exponentiation: s = group.random(ZR)
        start_time = time.perf_counter()
        s = group.random(ZR)
        end_time = time.perf_counter()
        self.exponentiation_time += end_time - start_time
        self.exponentiation_count += 1  # One exponentiation

        # Exponentiation: C = pk['h'] ** s
        start_time = time.perf_counter()
        C = pk['h'] ** s
        end_time = time.perf_counter()
        self.exponentiation_time += end_time - start_time
        self.exponentiation_count += 1  # One exponentiation

        C_y, C_y_pr = {}, {}
        shares = util.calculateSharesDict(s, policy)

        for i in shares.keys():
            j = util.strip_index(i)

            # Exponentiation: C_y[i] = pk['g'] ** shares[i]
            start_time = time.perf_counter()
            C_y[i] = pk['g'] ** shares[i]
            end_time = time.perf_counter()
            self.exponentiation_time += end_time - start_time
            self.exponentiation_count += 1  # One exponentiation

            # Exponentiation: C_y_pr[i] = group.hash(j, G2) ** shares[i]
            start_time = time.perf_counter()
            C_y_pr[i] = group.hash(j, G2) ** shares[i]
            end_time = time.perf_counter()
            self.exponentiation_time += end_time - start_time
            self.exponentiation_count += 1  # One exponentiation

        # Exponentiation: e_gg_alpha_s = pk['e_gg_alpha'] ** s
        start_time = time.perf_counter()
        e_gg_alpha_s = pk['e_gg_alpha'] ** s
        end_time = time.perf_counter()
        self.exponentiation_time += end_time - start_time
        self.exponentiation_count += 1  # One exponentiation

        # Multiplication: C_tilde = e_gg_alpha_s * M
        start_time = time.perf_counter()
        C_tilde = e_gg_alpha_s * M
        end_time = time.perf_counter()
        self.multiplication_time += end_time - start_time
        self.multiplication_count += 1  # One multiplication

        return {
            'C_tilde': C_tilde,
            'C': C,
            'Cy': C_y,
            'Cyp': C_y_pr,
            'policy': policy_str,
        }

    def decrypt(self, pk, sk, ct):
        # Policy creation (Not timed)
        policy = util.createPolicy(ct['policy'])

        # Prune the policy (Not timed)
        pruned_list = util.prune(policy, sk['S'])

        if pruned_list == False:
            return False

        # Get coefficients (Not timed)
        z = util.getCoefficients(policy)

        A = group.init(GT, 1)  # Initialize A in GT

        for i in pruned_list:
            j = i.getAttributeAndIndex()
            k = i.getAttribute()

            # Pairing: pair1 = pair(ct['Cy'][j], sk['Dj'][k])
            start_time = time.perf_counter()
            pair1 = pair(ct['Cy'][j], sk['Dj'][k])
            end_time = time.perf_counter()
            self.pairing_time += end_time - start_time
            self.pairing_count += 1  # One pairing

            # Pairing: pair2 = pair(sk['Djp'][k], ct['Cyp'][j])
            start_time = time.perf_counter()
            pair2 = pair(sk['Djp'][k], ct['Cyp'][j])
            end_time = time.perf_counter()
            self.pairing_time += end_time - start_time
            self.pairing_count += 1  # One pairing

            # Division: ratio = pair1 / pair2 (treated as multiplication for timing)
            start_time = time.perf_counter()
            ratio = pair1 / pair2
            end_time = time.perf_counter()
            self.multiplication_time += end_time - start_time
            self.multiplication_count += 1  # One multiplication

            # Exponentiation: ratio_z = ratio ** z[j]
            start_time = time.perf_counter()
            ratio_z = ratio ** z[j]
            end_time = time.perf_counter()
            self.exponentiation_time += end_time - start_time
            self.exponentiation_count += 1  # One exponentiation

            # Multiplication: A *= ratio_z
            start_time = time.perf_counter()
            A *= ratio_z
            end_time = time.perf_counter()
            self.multiplication_time += end_time - start_time
            self.multiplication_count += 1  # One multiplication

        # Pairing: pair_final = pair(ct['C'], sk['D'])
        start_time = time.perf_counter()
        pair_final = pair(ct['C'], sk['D'])
        end_time = time.perf_counter()
        self.pairing_time += end_time - start_time
        self.pairing_count += 1  # One pairing

        # Division: denominator = pair_final / A (treated as multiplication for timing)
        start_time = time.perf_counter()
        denominator = pair_final / A
        end_time = time.perf_counter()
        self.multiplication_time += end_time - start_time
        self.multiplication_count += 1  # One multiplication

        # Final Division: decrypted = ct['C_tilde'] / denominator (treated as multiplication for timing)
        start_time = time.perf_counter()
        decrypted = ct['C_tilde'] / denominator
        end_time = time.perf_counter()
        self.multiplication_time += end_time - start_time
        self.multiplication_count += 1  # One multiplication

        return decrypted

    def report_timings(self):
        print("\n=== CP-ABE Operation Timings ===")
        
        if self.pairing_count > 0:
            total_pairing_ms = self.pairing_time * 1000
            print(f"Bilinear Pairings Total Time: {total_pairing_ms:.3f} ms over {self.pairing_count} operations")
        else:
            print("Bilinear Pairings Total Time: 0.000 ms over 0 operations")
        
        if self.exponentiation_count > 0:
            total_exponentiation_ms = self.exponentiation_time * 1000
            print(f"Exponentiations Total Time: {total_exponentiation_ms:.3f} ms over {self.exponentiation_count} operations")
        else:
            print("Exponentiations Total Time: 0.000 ms over 0 operations")
        
        if self.multiplication_count > 0:
            total_multiplication_ms = self.multiplication_time * 1000
            print(f"Multiplications Total Time: {total_multiplication_ms:.3f} ms over {self.multiplication_count} operations")
        else:
            print("Multiplications Total Time: 0.000 ms over 0 operations")
        
        print("=================================\n")
    
        # Reset timers and counters after reporting
        self.pairing_time = 0.0
        self.exponentiation_time = 0.0
        self.multiplication_time = 0.0
        
        self.pairing_count = 0
        self.exponentiation_count = 0
        self.multiplication_count = 0

# Tkinter GUI
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        blur_faces(file_path)

def blur_faces(image_path):
    global original_image, blurred_image, face_regions, policies, hash_map, ciphertext_map

    # Reset maps for new image
    hash_map = {}
    ciphertext_map = []

    # Load and prepare image
    original_image = cv2.imread(image_path)
    if original_image is None:
        messagebox.showerror("Error", "Cannot open image.")
        return
    original_image = resize_image(original_image, width=800, height=600)

    # Load face detector model
    prototxt_path = 'deploy.prototxt.txt'  # Updated to relative path
    model_path = 'res10_300x300_ssd_iter_140000.caffemodel'  # Updated to relative path

    if not os.path.exists(prototxt_path) or not os.path.exists(model_path):
        messagebox.showerror("Error", "Model files not found.")
        return

    face_net = cv2.dnn.readNetFromCaffe(prototxt_path, model_path)
    h, w = original_image.shape[:2]
    blob = cv2.dnn.blobFromImage(original_image, 1.0, (300, 300), (104.0, 177.0, 123.0))
    face_net.setInput(blob)
    detections = face_net.forward()

    blurred_image = original_image.copy()
    face_regions = []

    # Process each detected face
    for i in range(detections.shape[2]):
        confidence = detections[0, 0, i, 2]
        if confidence > 0.5:
            box = detections[0, 0, i, 3:7] * np.array([w, h, w, h])
            (x, y, x1, y1) = box.astype("int")
            x, y, x1, y1 = max(0, x), max(0, y), min(w, x1), min(h, y1)
            if x < x1 and y < y1:
                face_roi = blurred_image[y:y1, x:x1]
                face_blur = cv2.GaussianBlur(face_roi, (99, 99), 30)
                blurred_image[y:y1, x:x1] = face_blur
                face_regions.append((x, y, x1, y1))
                
                # Compute hash of the original face region
                original_face_region = original_image[y:y1, x:x1]
                hash_value = group.hash(original_face_region.tobytes(), ZR)
                
                # Compute M for encryption
                M = pair(pk['g'], pk['g2']) ** hash_value
                
                # Store hash and ciphertext in the respective maps
                face_index = len(face_regions)  # 1-based indexing for buttons
                hash_map[face_index] = M
                policy_str = policies[(face_index - 1) % len(policies)]
                ct = cpabe.encrypt(pk, M, policy_str)
                ciphertext_map.append(ct)

                # After encryption, report timing
                cpabe.report_timings()  # Reports timings in ms

    # Sort faces and update display
    face_regions.sort(key=lambda box: box[0])
    update_display(blurred_image)

    # Add buttons for unblurring
    for widget in frame_buttons.winfo_children():
        widget.destroy()

    if face_regions:
        for idx in range(len(face_regions)):
            btn_unblur = tk.Button(
                frame_buttons, 
                text=f"Unblur Face {idx + 1}", 
                command=lambda i=idx + 1: unblur_face(i)
            )
            btn_unblur.pack(side=tk.LEFT, padx=5, pady=5)
    else:
        messagebox.showinfo("Info", "No faces detected.")

def unblur_face(face_number):
    global blurred_image, pk, mk, hash_map, ciphertext_map

    try:
        # Retrieve the ciphertext for the selected face
        ct = ciphertext_map[face_number - 1]
    except IndexError:
        messagebox.showerror("Error", f"No ciphertext found for Face {face_number}.")
        return

    # Get user attributes for decryption
    attributes = simpledialog.askstring("Input", f"Enter attributes for Face {face_number} separated by commas:")
    if not attributes:
        return

    attribute_list = [attr.strip().upper() for attr in attributes.split(",")]

    # Generate user's secret key
    try:
        sk = cpabe.keygen(pk, mk, attribute_list)
        print(f"Generated Secret Key for face {face_number}: {sk}")
    except Exception as e:
        messagebox.showerror("Error", f"Key generation failed:\n{str(e)}")
        return

    # Attempt to decrypt the ciphertext
    try:
        rec_msg = cpabe.decrypt(pk, sk, ct)
        print(f"Decrypted message for face {face_number}: {rec_msg}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")
        return

    # Report timing after decryption
    cpabe.report_timings()  # Reports timings in ms

    # Verify the decrypted message against the stored hash
    if rec_msg:
        expected_msg = hash_map.get(face_number, None)
        if expected_msg and group.serialize(rec_msg) == group.serialize(expected_msg):
            # If the message matches, unblur the face
            (x, y, x1, y1) = face_regions[face_number - 1]
            blurred_image[y:y1, x:x1] = original_image[y:y1, x:x1]
            update_display(blurred_image)
            print(f"Face {face_number} successfully unblurred.")
            messagebox.showinfo("Success", f"Face {face_number} successfully unblurred.")
        else:
            messagebox.showerror("Error", "Decryption succeeded, but the message does not match the expected value. Incorrect attributes.")
    else:
        messagebox.showerror("Error", "Decryption returned no result.")

def resize_image(image, width=800, height=600):
    # Resize image while maintaining aspect ratio
    h, w = image.shape[:2]
    aspect_ratio = w / h
    if (width / height) > aspect_ratio:
        new_height = height
        new_width = int(aspect_ratio * height)
    else:
        new_width = width
        new_height = int(width / aspect_ratio)
    resized_image = cv2.resize(image, (new_width, new_height))
    return resized_image

def update_display(image):
    image_rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    image_pil = Image.fromarray(image_rgb)
    image_tk = ImageTk.PhotoImage(image_pil)
    
    label_image.config(image=image_tk)
    label_image.image = image_tk

def benchmark_multiplications():
    test_element1 = group.random(GT)
    test_element2 = group.random(GT)
    num_repeats = 100000  # Number of multiplications
    total_time = 0.0
    for _ in range(num_repeats):
        start_time = time.perf_counter()
        result = test_element1 * test_element2
        end_time = time.perf_counter()
        total_time += end_time - start_time
    average_time_ms = (total_time / num_repeats) * 1000
    print(f"Average Multiplication Time: {average_time_ms:.6f} ms over {num_repeats} repetitions")

def main():
    initialize_cpabe()
    
    # Tkinter setup
    root = tk.Tk()
    root.title("Face Blurring Tool")
    root.geometry("1000x700")
    
    btn_select = tk.Button(root, text="Select Image", command=select_file)
    btn_select.pack(pady=10)
    
    global label_image
    label_image = tk.Label(root)
    label_image.pack(side=tk.TOP, pady=10)
    
    global frame_buttons
    frame_buttons = tk.Frame(root)
    frame_buttons.pack(side=tk.BOTTOM, fill=tk.X, pady=10, anchor='s')
    
    root.mainloop()
    
    # Optional: Run multiplication benchmark after GUI closes
    # benchmark_multiplications()

if __name__ == "__main__":
    main()
