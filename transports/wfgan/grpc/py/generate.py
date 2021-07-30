import numpy as np
import torch
from model import *
import joblib
from os.path import join, abspath, dirname, pardir

BASE_DIR = abspath(join(dirname(__file__), pardir))

device = torch.device('cuda:0' if torch.cuda.is_available() else 'cpu')
latent_dim = 50
seq_len = 1401
class_dim = 500
CELL_SIZE = 536  # a minimum cell size
model_id = 'training_0729_133623'
model_relpath = 'py/{}/generator_seqlen{}_cls{}_latentdim{}.ckpt'.format(model_id, seq_len, class_dim, latent_dim)
scaler_relpath = 'py/{}/scaler.gz'.format(model_id)
model_path = join(BASE_DIR, model_relpath)
scaler_path = join(BASE_DIR, scaler_relpath)


def sample():
    # load model
    n = 1
    scaler = joblib.load(scaler_path)
    model = Generator(seq_len, class_dim, latent_dim).to(device)
    model.load_state_dict(torch.load(model_path, map_location=device))
    c_ind = np.random.randint(class_dim)
    model.eval()
    with torch.no_grad():
        z = np.random.randn(n, latent_dim).astype('float32')
        z = torch.from_numpy(z).to(device)
        c = torch.zeros(n, class_dim)
        c[:, c_ind] = 1
        c = c.to(device)
        synthesized_x = model(z, c).cpu().numpy()
        synthesized_x = scaler.inverse_transform(synthesized_x).flatten()
        length = min(int(synthesized_x[0]), seq_len - 1)
        if length % 2 != 0:
            length -= 1
        assert length % 2 == 0
        # print(length)
        # print(synthesized_x[1:1+length].astype(int),'\n', synthesized_x[1+length:].astype(int))
        synthesized_x = synthesized_x[1:1 + length].astype(int)
        synthesized_x[synthesized_x < CELL_SIZE] = CELL_SIZE
    return (synthesized_x.tolist())

# if __name__ == '__main__':
#     print(sample())
