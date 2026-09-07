## Verdict

The finding is a true positive. The application loads untrusted bytes directly into an assembly and executes arbitrary methods by reflection, allowing code injection.

## Source

The vulnerability originates from the uploaded file (`IFormFile pluginFile` at line 22), which is read into `uploadedBytes` (lines 30-34) with no validation on its content or origin.

## Fix

**Step 1: Define a required plugin interface**

Before the `PluginController` class, add:

```csharp
namespace PluginHost.Interfaces
{
    public interface IPlugin
    {
        object Initialize();
    }
}
```

**Step 2: Replace the vulnerable code**

Replace lines 36-48 with:

```csharp
            // Load the assembly from untrusted bytes
            Assembly pluginAssembly = Assembly.Load(uploadedBytes);

            // Enforce that the plugin implements a known, safe interface
            Type pluginInterfaceType = typeof(IPlugin);
            
            foreach (Type candidateType in pluginAssembly.GetExportedTypes())
            {
                // Only accept types that explicitly implement IPlugin
                if (!pluginInterfaceType.IsAssignableFrom(candidateType) || candidateType.IsInterface)
                {
                    continue;
                }

                try
                {
                    // Instantiate only safe plugin types
                    IPlugin plugin = (IPlugin)Activator.CreateInstance(candidateType);
                    object result = plugin.Initialize();
                    return Ok(new { loadedType = candidateType.FullName, result });
                }
                catch (Exception ex)
                {
                    return BadRequest($"Plugin initialization failed: {ex.Message}");
                }
            }

            return UnprocessableEntity($"No type implementing IPlugin was found.");
```

## Explanation

The original code accepts arbitrary compiled assemblies and invokes any public static method named "Initialize", giving the uploaded code direct execution access to the application context. The fix replaces unconstrained reflection with an interface contract: plugins must explicitly implement `IPlugin` and its `Initialize()` method. This enforces a known, vetted entry point and prevents execution of arbitrary methods. The application controls the method signature and return type, and unknown assemblies that do not implement the interface are rejected. While `Assembly.Load()` still loads the bytes, only types that match the safety contract are instantiated and invoked.

## Behaviour changes

- Plugins must now implement the `IPlugin` interface; existing plugin assemblies that only expose a public static `Initialize()` method will no longer load.
- The return type is constrained to `object`, matching the interface contract, rather than allowing arbitrary methods with any signature.
- Exceptions during plugin instantiation or initialization are caught and returned as HTTP 400 Bad Request instead of propagating unhandled.
- The success case returns the plugin's fully qualified type name and the result object, same as before.
