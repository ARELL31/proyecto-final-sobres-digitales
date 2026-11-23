"""Punto de entrada: inicia la interfaz web del sobre digital."""
from gui import crear_app

if __name__ == "__main__":
    print("Abre http://127.0.0.1:5000 en tu navegador")
    crear_app().run(host="127.0.0.1", port=5000, debug=False)
