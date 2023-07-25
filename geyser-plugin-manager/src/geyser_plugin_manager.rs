use {
    jsonrpc_core::{ErrorCode, Result as JsonRpcResult},
    jsonrpc_server_utils::tokio::sync::oneshot::Sender as OneShotSender,
    libloading::Library,
    log::*,
    solana_geyser_plugin_interface::geyser_plugin_interface::GeyserPlugin,
    std::path::Path,
};

#[derive(Default, Debug)]
pub struct GeyserPluginManager {
    pub plugins: Vec<Box<dyn GeyserPlugin>>,
    libs: Vec<Library>,
}

impl GeyserPluginManager {
    pub fn new() -> Self {
        GeyserPluginManager {
            plugins: Vec::default(),
            libs: Vec::default(),
        }
    }

    /// Unload all plugins and loaded plugin libraries, making sure to fire
    /// their `on_plugin_unload()` methods so they can do any necessary cleanup.
    pub fn unload(&mut self) {
        for mut plugin in self.plugins.drain(..) {
            info!("Unloading plugin for {:?}", plugin.name());
            plugin.on_unload();
        }

        for lib in self.libs.drain(..) {
            drop(lib);
        }
    }

    /// Check if there is any plugin interested in account data
    pub fn account_data_notifications_enabled(&self) -> bool {
        for plugin in &self.plugins {
            if plugin.account_data_notifications_enabled() {
                return true;
            }
        }
        false
    }

    /// Check if there is any plugin interested in transaction data
    pub fn transaction_notifications_enabled(&self) -> bool {
        for plugin in &self.plugins {
            if plugin.transaction_notifications_enabled() {
                return true;
            }
        }
        false
    }

    /// Check if there is any plugin interested in entry data
    pub fn entry_notifications_enabled(&self) -> bool {
        for plugin in &self.plugins {
            if plugin.entry_notifications_enabled() {
                return true;
            }
        }
        false
    }

    /// Admin RPC request handler
    pub(crate) fn list_plugins(&self) -> JsonRpcResult<Vec<String>> {
        Ok(self.plugins.iter().map(|p| p.name().to_owned()).collect())
    }

    /// Admin RPC request handler
    /// # Safety
    ///
    /// This function loads the dynamically linked library specified in the path. The library
    /// must do necessary initializations.
    ///
    /// The string returned is the name of the plugin loaded, which can only be accessed once
    /// the plugin has been loaded and calling the name method.
    pub(crate) fn load_plugin(
        &mut self,
        geyser_plugin_config_file: impl AsRef<Path>,
    ) -> JsonRpcResult<String> {
        // First load plugin
        let (mut new_plugin, new_lib, new_config_file) =
            load_plugin_from_config(geyser_plugin_config_file.as_ref()).map_err(|e| {
                jsonrpc_core::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("Failed to load plugin: {e}"),
                    data: None,
                }
            })?;

        // Then see if a plugin with this name already exists. If so, abort
        if self
            .plugins
            .iter()
            .any(|plugin| plugin.name().eq(new_plugin.name()))
        {
            return Err(jsonrpc_core::Error {
                code: ErrorCode::InvalidRequest,
                message: format!(
                    "There already exists a plugin named {} loaded. Did not load requested plugin",
                    new_plugin.name()
                ),
                data: None,
            });
        }

        // Call on_load and push plugin
        new_plugin
            .on_load(new_config_file)
            .map_err(|on_load_err| jsonrpc_core::Error {
                code: ErrorCode::InvalidRequest,
                message: format!(
                    "on_load method of plugin {} failed: {on_load_err}",
                    new_plugin.name()
                ),
                data: None,
            })?;
        let name = new_plugin.name().to_string();
        self.plugins.push(new_plugin);
        self.libs.push(new_lib);

        Ok(name)
    }

    pub(crate) fn unload_plugin(&mut self, name: &str) -> JsonRpcResult<()> {
        // Check if any plugin names match this one
        let Some(idx) = self.plugins.iter().position(|plugin| plugin.name().eq(name)) else {
            // If we don't find one return an error
            return Err(
                jsonrpc_core::error::Error {
                    code: ErrorCode::InvalidRequest,
                    message: String::from("The plugin you requested to unload is not loaded"),
                    data: None,
                }
            )
        };

        // Unload and drop plugin and lib
        self._drop_plugin(idx);

        Ok(())
    }

    /// Checks for a plugin with a given `name`.
    /// If it exists, first unload it.
    /// Then, attempt to load a new plugin
    pub(crate) fn reload_plugin(&mut self, name: &str, config_file: &str) -> JsonRpcResult<()> {
        // Check if any plugin names match this one
        let Some(idx) = self.plugins.iter().position(|plugin| plugin.name().eq(name)) else {
            // If we don't find one return an error
            return Err(
                jsonrpc_core::error::Error {
                    code: ErrorCode::InvalidRequest,
                    message: String::from("The plugin you requested to reload is not loaded"),
                    data: None,
                }
            )
        };

        // Unload and drop current plugin first in case plugin requires exclusive access to resource,
        // such as a particular port or database.
        self._drop_plugin(idx);

        // Try to load plugin, library
        // SAFETY: It is up to the validator to ensure this is a valid plugin library.
        let (mut new_plugin, new_lib, new_parsed_config_file) =
            load_plugin_from_config(config_file.as_ref()).map_err(|err| jsonrpc_core::Error {
                code: ErrorCode::InvalidRequest,
                message: err.to_string(),
                data: None,
            })?;

        // Attempt to on_load with new plugin
        match new_plugin.on_load(new_parsed_config_file) {
            // On success, push plugin and library
            Ok(()) => {
                self.plugins.push(new_plugin);
                self.libs.push(new_lib);
            }

            // On failure, return error
            Err(err) => {
                return Err(jsonrpc_core::error::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!(
                        "Failed to start new plugin (previous plugin was dropped!): {err}"
                    ),
                    data: None,
                });
            }
        }

        Ok(())
    }

    fn _drop_plugin(&mut self, idx: usize) {
        let mut current_plugin = self.plugins.remove(idx);
        let _current_lib = self.libs.remove(idx);
        current_plugin.on_unload();
    }
}

#[derive(Debug)]
pub enum GeyserPluginManagerRequest {
    ReloadPlugin {
        name: String,
        config_file: String,
        response_sender: OneShotSender<JsonRpcResult<()>>,
    },
    UnloadPlugin {
        name: String,
        response_sender: OneShotSender<JsonRpcResult<()>>,
    },
    LoadPlugin {
        config_file: String,
        response_sender: OneShotSender<JsonRpcResult<String>>,
    },
    ListPlugins {
        response_sender: OneShotSender<JsonRpcResult<Vec<String>>>,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum GeyserPluginManagerError {
    #[error("Cannot open the the plugin config file")]
    CannotOpenConfigFile(String),

    #[error("Cannot read the the plugin config file")]
    CannotReadConfigFile(String),

    #[error("The config file is not in a valid Json format")]
    InvalidConfigFileFormat(String),

    #[error("Plugin library path is not specified in the config file")]
    LibPathNotSet,

    #[error("Invalid plugin path")]
    InvalidPluginPath,

    #[error("Cannot load plugin shared library")]
    PluginLoadError(String),

    #[error("The geyser plugin {0} is already loaded shared library")]
    PluginAlreadyLoaded(String),

    #[error("The GeyserPlugin on_load method failed")]
    PluginStartError(String),
}

/// # Safety
///
/// This function loads the dynamically linked library specified in the path. The library
/// must do necessary initializations.
///
/// This returns the geyser plugin, the dynamic library, and the parsed config file as a &str.
/// (The geyser plugin interface requires a &str for the on_load method).
pub(crate) fn load_plugin_from_config(
    geyser_plugin_config_file: &Path,
) -> Result<(Box<dyn GeyserPlugin>, Library, &str), GeyserPluginManagerError> {
    use std::{fs::File, io::Read, path::PathBuf};
    type PluginConstructor = unsafe fn() -> *mut dyn GeyserPlugin;
    use libloading::Symbol;

    let mut file = match File::open(geyser_plugin_config_file) {
        Ok(file) => file,
        Err(err) => {
            return Err(GeyserPluginManagerError::CannotOpenConfigFile(format!(
                "Failed to open the plugin config file {geyser_plugin_config_file:?}, error: {err:?}"
            )));
        }
    };

    let mut contents = String::new();
    if let Err(err) = file.read_to_string(&mut contents) {
        return Err(GeyserPluginManagerError::CannotReadConfigFile(format!(
            "Failed to read the plugin config file {geyser_plugin_config_file:?}, error: {err:?}"
        )));
    }

    let result: serde_json::Value = match json5::from_str(&contents) {
        Ok(value) => value,
        Err(err) => {
            return Err(GeyserPluginManagerError::InvalidConfigFileFormat(format!(
                "The config file {geyser_plugin_config_file:?} is not in a valid Json5 format, error: {err:?}"
            )));
        }
    };

    let libpath = result["libpath"]
        .as_str()
        .ok_or(GeyserPluginManagerError::LibPathNotSet)?;
    let mut libpath = PathBuf::from(libpath);
    if libpath.is_relative() {
        let config_dir = geyser_plugin_config_file.parent().ok_or_else(|| {
            GeyserPluginManagerError::CannotOpenConfigFile(format!(
                "Failed to resolve parent of {geyser_plugin_config_file:?}",
            ))
        })?;
        libpath = config_dir.join(libpath);
    }

    let config_file = geyser_plugin_config_file
        .as_os_str()
        .to_str()
        .ok_or(GeyserPluginManagerError::InvalidPluginPath)?;

    let (plugin, lib) = unsafe {
        let lib = Library::new(libpath)
            .map_err(|e| GeyserPluginManagerError::PluginLoadError(e.to_string()))?;
        let constructor: Symbol<PluginConstructor> = lib
            .get(b"_create_plugin")
            .map_err(|e| GeyserPluginManagerError::PluginLoadError(e.to_string()))?;
        let plugin_raw = constructor();
        (Box::from_raw(plugin_raw), lib)
    };
    Ok((plugin, lib, config_file))
}

// This is mocked for tests to avoid having to do IO with a dynamically linked library
// across different architectures at test time
//
