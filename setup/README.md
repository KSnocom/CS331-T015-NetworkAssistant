# 1. Install docker

```bash
sudo dnf install -y git python3 python3-pip

sudo dnf config-manager addrepo \
  --from-repofile=https://download.docker.com/linux/fedora/docker-ce.repo

sudo dnf install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

sudo systemctl enable --now docker

sudo usermod -aG docker "$USER"
newgrp docker
```

# 2. Install OLLAMA and Qwen

```bash
curl -fsSL https://ollama.com/install.sh | sh

sudo systemctl enable --now ollama

ollama pull qwen3:4b
ollama list
```

# 3. Download the code

```bash
git clone https://github.com/KSnocom/CS331-T001-NetworkAssistant.git

cd CS331-T015-NetworkAssistant/code
```

# 4. Create python environtment

```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

# 5. Run the lab

```bash
mkdir -p logs

docker compose -f docker/docker-compose.yml up -d --build

docker compose -f docker/docker-compose.yml ps
```

# 6. Launch

```bash
python -m src.chat --mode live
```
