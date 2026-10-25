def run(x)
  y = 1
  eval(x)
end

def load(data)
  Marshal.load(data)
end
