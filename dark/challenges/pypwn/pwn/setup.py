from distutils.core import setup, Extension
note_module = Extension('_note',
   sources=['note_wrap.c', 'note.c'],
)
setup (name = 'note',
   version = '0.1',
   author = "SWIG Docs",
   description = """Simple swig example from docs""",
   ext_modules = [note_module],
   py_modules = ["note"],
)
