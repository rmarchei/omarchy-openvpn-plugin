import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "rmarchei.openvpn"
  ipcTarget: "rmarchei.openvpn"
  manageIpc: false

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property string helperPath: String(Qt.resolvedUrl("scripts/openvpn-plugin")).replace(/^file:\/\//, "")
  readonly property string configDirectory: String(setting("configDirectory", "~/.config/openvpn"))
  readonly property int refreshIntervalSec: Math.max(5, Number(setting("refreshIntervalSec", 10)) || 10)
  readonly property bool singleConnection: setting("singleConnection", true) !== false
  readonly property var activeProfiles: profiles.filter(function(profile) { return profile.active })
  readonly property bool anyActive: activeProfiles.length > 0
  readonly property bool connecting: actionKind === "connect" || activeProfiles.some(function(profile) { return profile.state === "activating" })

  property var profiles: []
  property bool directoryExists: true
  property string editPath: ""
  property string editName: ""
  property var editFields: []
  property string renamePath: ""
  property string renameText: ""
  property string usernameText: ""
  property string passwordText: ""
  property string passphraseText: ""
  property string forgetPath: ""
  property string message: ""
  // Action errors last until the panel closes or the next action starts;
  // list errors until the backend answers a refresh again.
  property string errorMessage: ""
  property string listErrorMessage: ""
  readonly property string shownError: errorMessage !== "" ? errorMessage : listErrorMessage
  property string actionKind: ""
  property string actionPath: ""
  property string actionInput: ""
  property bool connectAfterSave: false

  implicitWidth: barButton.implicitWidth
  implicitHeight: barButton.implicitHeight

  function parseResult(raw) {
    try {
      return JSON.parse(String(raw || "{}"))
    } catch (error) {
      return { ok: false, error: "The OpenVPN backend returned invalid data" }
    }
  }

  function refresh() {
    if (listProcess.running) return
    listProcess.command = [helperPath, "list", "--config-dir", configDirectory]
    listProcess.running = true
  }

  function heroTitle() {
    if (activeProfiles.length === 0) return "OpenVPN"
    return activeProfiles.map(function(profile) { return profile.name }).join(" · ")
  }

  function heroMeta() {
    if (connecting) return "Connecting"
    if (activeProfiles.length > 1) return activeProfiles.length + " connected"
    return anyActive ? "Connected" : "Disconnected"
  }

  function authLabel(profile) {
    switch (profile.auth) {
    case "certificate": return profile.pkcs12 ? "PKCS#12 certificate" : "Certificate"
    case "password-certificate": return "Certificate + password"
    case "password": return "Password"
    case "static-key": return "Static key"
    default: return "No authentication"
    }
  }

  function missingSecrets(profile) {
    return profile.requiredSecrets.filter(function(name) { return profile.storedSecrets.indexOf(name) < 0 })
  }

  function statusLabel(profile) {
    if (actionPath === profile.path && actionKind === "connect") return "Connecting…"
    if (actionPath === profile.path && actionKind === "disconnect") return "Disconnecting…"
    if (profile.state === "activating") return "Connecting…"
    if (profile.active) return "Connected"
    if (profile.problems.length > 0) return profile.problems[0]
    if (profile.requiredSecrets.length === 0) return "Ready"
    if (profile.hasSecrets) return "Credentials saved"
    var missing = missingSecrets(profile)
    if (missing.length === 1 && missing[0] === "cert-pass") return "Key passphrase required"
    return "Credentials required"
  }

  function needs(field) {
    return editFields.indexOf(field) >= 0
  }

  function firstEditField() {
    if (needs("username")) return usernameField
    if (needs("password")) return passwordField
    return passphraseField
  }

  function openCredentials(profile, thenConnect) {
    closeRename()
    forgetPath = ""
    editPath = profile.path
    editName = profile.name
    editFields = profile.requiredSecrets
    usernameText = ""
    passwordText = ""
    passphraseText = ""
    connectAfterSave = thenConnect === true
    Qt.callLater(function() { root.firstEditField().forceActiveFocus() })
  }

  function closeCredentials() {
    editPath = ""
    editName = ""
    editFields = []
    usernameText = ""
    passwordText = ""
    passphraseText = ""
    connectAfterSave = false
    if (opened) Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function openRename(profile) {
    closeCredentials()
    forgetPath = ""
    renamePath = profile.path
    renameText = profile.name
    Qt.callLater(function() {
      profileNameField.forceActiveFocus()
      profileNameField.selectAll()
    })
  }

  function closeRename() {
    renamePath = ""
    renameText = ""
    if (opened && editPath === "") Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function saveRename() {
    var name = renameText.trim()
    if (name === "") {
      errorMessage = "Profile name is required"
      return
    }
    runAction("rename", renamePath, JSON.stringify({ name: name }) + "\n")
  }

  function actionCommand(kind, path) {
    if (kind === "disconnect-all") return [helperPath, kind]
    if (kind === "create-directory") return [helperPath, kind, "--config-dir", configDirectory]
    if (kind === "add-profile") return [helperPath, kind, "--source", path, "--config-dir", configDirectory]
    var command = [helperPath, kind, "--config", path, "--config-dir", configDirectory]
    if (kind === "connect" && singleConnection) command.push("--exclusive")
    return command
  }

  function runAction(kind, path, input) {
    if (actionProcess.running) return
    actionKind = kind
    actionPath = path || ""
    actionInput = input || ""
    message = ""
    errorMessage = ""
    actionProcess.command = actionCommand(kind, actionPath)
    actionProcess.running = true
  }

  // Opens the desktop file chooser; the chosen profile or zip bundle is then
  // copied into the profiles directory by the add-profile action. The panel
  // steps aside while the dialog is up and comes back with the result.
  function addProfile() {
    if (pickProcess.running || actionProcess.running) return
    closeCredentials()
    closeRename()
    pickProcess.running = true
    close()
  }

  function activate(profile) {
    if (!profile || actionProcess.running) return
    forgetPath = ""
    if (profile.active || profile.state === "activating") runAction("disconnect", profile.path)
    else if (profile.problems.length > 0) errorMessage = profile.problems[0]
    else if (profile.hasSecrets) runAction("connect", profile.path)
    else openCredentials(profile, true)
  }

  function forget(profile) {
    if (forgetPath !== profile.path) {
      forgetPath = profile.path
      return
    }
    forgetPath = ""
    runAction("forget", profile.path)
  }

  function saveCredentials() {
    var labels = { username: "Username", password: "Password", "cert-pass": "Key passphrase" }
    var values = { username: usernameText.trim(), password: passwordText, "cert-pass": passphraseText }
    for (var index = 0; index < editFields.length; index++) {
      if (values[editFields[index]] === "") {
        errorMessage = labels[editFields[index]] + " is required"
        return
      }
    }
    var payload = JSON.stringify({ username: values.username, password: values.password, passphrase: values["cert-pass"] }) + "\n"
    usernameText = ""
    passwordText = ""
    passphraseText = ""
    runAction("save-credentials", editPath, payload)
  }

  onOpenedChanged: {
    forgetPath = ""
    if (opened) {
      refresh()
    } else {
      message = ""
      errorMessage = ""
    }
  }

  onMessageChanged: if (message !== "") messageTimer.restart()

  Timer {
    id: messageTimer
    interval: 4000
    onTriggered: root.message = ""
  }

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): string { root.refresh(); return "ok" }
    function disconnectAll(): string { root.runAction("disconnect-all", ""); return "ok" }
  }

  Process {
    id: listProcess
    running: false
    command: []
    stdout: StdioCollector { id: listOutput; waitForEnd: true }
    stderr: StdioCollector { id: listError; waitForEnd: true }
    onExited: function(exitCode) {
      var result = root.parseResult(listOutput.text)
      if (exitCode === 0 && result.ok) {
        root.profiles = result.profiles || []
        // A missing directory is the normal first-run state, not an error.
        root.directoryExists = result.directoryExists !== false
        root.listErrorMessage = ""
      } else {
        root.listErrorMessage = result.error || String(listError.text || "Could not load OpenVPN profiles").trim()
      }
    }
  }

  Process {
    id: pickProcess
    running: false
    command: [root.helperPath, "pick-file"]
    stdout: StdioCollector { id: pickOutput; waitForEnd: true }
    stderr: StdioCollector { id: pickError; waitForEnd: true }
    onExited: function(exitCode) {
      var result = root.parseResult(pickOutput.text)
      root.open()
      if (exitCode === 0 && result.ok) {
        if (result.path) root.runAction("add-profile", result.path)
      } else {
        root.errorMessage = result.error || String(pickError.text || "Could not open the file chooser").trim()
      }
    }
  }

  Process {
    id: actionProcess
    running: false
    command: []
    stdinEnabled: true
    stdout: StdioCollector { id: actionOutput; waitForEnd: true }
    stderr: StdioCollector { id: actionError; waitForEnd: true }
    onStarted: {
      if (root.actionInput !== "") {
        write(root.actionInput)
        root.actionInput = ""
      }
    }
    onExited: function(exitCode) {
      var completedKind = root.actionKind
      var completedPath = root.actionPath
      var shouldConnect = completedKind === "save-credentials" && root.connectAfterSave
      var result = root.parseResult(actionOutput.text)
      root.actionKind = ""
      root.actionPath = ""
      if (exitCode === 0 && result.ok) {
        root.message = result.message || "Done"
        root.errorMessage = ""
        if (completedKind === "save-credentials") root.closeCredentials()
        if (completedKind === "rename") root.closeRename()
        if (shouldConnect) Qt.callLater(function() { root.runAction("connect", completedPath) })
        else root.refresh()
      } else {
        root.errorMessage = result.error || String(actionError.text || "OpenVPN action failed").trim()
        root.connectAfterSave = false
        root.refresh()
      }
    }
  }

  Timer {
    interval: root.refreshIntervalSec * 1000
    repeat: true
    running: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  BarIconButton {
    id: barButton
    anchors.fill: parent
    bar: root.bar
    text: root.anyActive ? "󰖂" : "󰦝"
    // `active` paints the icon in the urgent color, so it flags problems only;
    // the glyph alone shows whether a profile is connected.
    active: root.shownError !== ""
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.MiddleButton) root.refresh()
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: popup
    anchorItem: barButton
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: popup.fittedContentWidth(Style.space(420))
    contentHeight: popup.fittedContentHeight(contentColumn.implicitHeight, Style.space(640))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      blocked: root.editPath !== "" || root.renamePath !== ""
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(text) {
        if (text === "r" || text === "R") root.refresh()
        else if (text === "a" || text === "A") root.addProfile()
      }

      Flickable {
        anchors.fill: parent
        contentWidth: width
        contentHeight: contentColumn.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: contentColumn
          width: parent.width
          spacing: Style.space(12)

          Item {
            id: header
            width: parent.width
            implicitHeight: hero.implicitHeight
            // The hero's components are reached through `header` rather than
            // `root`, matching how the first-party panels expose panel state.
            readonly property bool anyActive: root.anyActive
            readonly property bool canDisconnectAll: root.activeProfiles.length > 1 && !actionProcess.running
            readonly property color iconColor: root.anyActive ? root.foreground : root.dim
            function disconnectAll() { root.runAction("disconnect-all", "") }

            PanelHero {
              id: hero
              width: parent.width
              title: root.heroTitle()
              meta: root.heroMeta()
              foreground: root.foreground
              fontFamily: root.fontFamily
              iconComponent: Component {
                Text {
                  text: header.anyActive ? "󰖂" : "󰦝"
                  color: header.iconColor
                  font.family: hero.fontFamily
                  font.pixelSize: Style.font.display
                }
              }
              trailingControl: Component {
                PanelActionButton {
                  visible: header.canDisconnectAll
                  iconText: "󰍃"
                  tooltipText: "Disconnect all"
                  foreground: hero.foreground
                  fontFamily: hero.fontFamily
                  onClicked: header.disconnectAll()
                }
              }
            }
          }

          Text {
            visible: root.message !== "" || root.shownError !== ""
            width: parent.width
            text: root.shownError !== "" ? root.shownError : root.message
            color: root.shownError !== "" ? root.urgent : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          PanelSeparator { width: parent.width; foreground: root.foreground }

          RowLayout {
            width: parent.width
            spacing: Style.space(8)

            PanelSectionHeader {
              Layout.fillWidth: true
              Layout.alignment: Qt.AlignVCenter
              text: "PROFILES"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            PanelActionButton {
              visible: root.profiles.length > 0
              enabled: !pickProcess.running && !actionProcess.running
              iconText: "󰐕"
              tooltipText: "Add profile (.ovpn, .conf or .zip)"
              foreground: root.foreground
              fontFamily: root.fontFamily
              Layout.alignment: Qt.AlignVCenter
              onClicked: root.addProfile()
            }
          }

          Text {
            visible: root.profiles.length === 0 && root.shownError === ""
            width: parent.width
            text: root.directoryExists
              ? "No profiles in " + root.configDirectory + " yet. Add an .ovpn, .conf or .zip bundle, or copy files there."
              : root.configDirectory + " does not exist yet. Add a profile to create it, or choose another directory in the widget settings."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
          }

          Row {
            visible: root.profiles.length === 0 && root.shownError === ""
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(8)

            Button {
              text: pickProcess.running ? "Choosing…" : "Add profile…"
              foreground: root.foreground
              fontFamily: root.fontFamily
              bordered: true
              enabled: !pickProcess.running && !actionProcess.running
              onClicked: root.addProfile()
            }
            Button {
              visible: !root.directoryExists
              text: "Create directory"
              foreground: root.foreground
              fontFamily: root.fontFamily
              enabled: !actionProcess.running
              onClicked: root.runAction("create-directory", "")
            }
          }

          Column {
            width: parent.width
            spacing: Style.space(6)

            Repeater {
              model: root.profiles

              CursorSurface {
                id: profileItem
                required property var modelData
                readonly property bool busy: root.actionPath === modelData.path
                readonly property bool live: modelData.active || modelData.state === "activating"
                readonly property bool confirmingForget: root.forgetPath === modelData.path
                width: parent.width
                implicitHeight: profileRow.implicitHeight + Style.space(12)
                current: modelData.active
                foreground: root.foreground

                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.activate(profileItem.modelData)
                }

                RowLayout {
                  id: profileRow
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  anchors.leftMargin: Style.space(8)
                  anchors.rightMargin: Style.space(6)
                  spacing: Style.space(8)

                  Text {
                    text: profileItem.live ? "󰖂" : (profileItem.modelData.auth === "password" ? "󰦝" : "󰄤")
                    color: profileItem.live ? root.foreground : root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.icon
                    Layout.alignment: Qt.AlignVCenter
                  }

                  ColumnLayout {
                    Layout.fillWidth: true
                    spacing: Style.space(1)

                    Text {
                      Layout.fillWidth: true
                      text: profileItem.modelData.name
                      color: root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      font.bold: profileItem.modelData.active
                      elide: Text.ElideRight
                    }
                    Text {
                      Layout.fillWidth: true
                      text: root.authLabel(profileItem.modelData) + " · " + root.statusLabel(profileItem.modelData)
                      color: profileItem.modelData.problems.length > 0 && !profileItem.live ? root.urgent : root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      elide: Text.ElideRight
                    }
                  }

                  PanelActionButton {
                    visible: !profileItem.live
                    enabled: !actionProcess.running && profileItem.modelData.problems.length === 0
                    iconText: "󰍂"
                    tooltipText: "Connect"
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    Layout.alignment: Qt.AlignVCenter
                    onClicked: root.activate(profileItem.modelData)
                  }

                  PanelActionButton {
                    visible: !profileItem.live
                    iconText: "󰏫"
                    tooltipText: "Rename profile"
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    Layout.alignment: Qt.AlignVCenter
                    onClicked: root.openRename(profileItem.modelData)
                  }

                  PanelActionButton {
                    visible: !profileItem.live && profileItem.modelData.requiredSecrets.length > 0
                    iconText: "󰌆"
                    tooltipText: profileItem.modelData.auth === "certificate" ? "Edit key passphrase" : "Edit keyring credentials"
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    Layout.alignment: Qt.AlignVCenter
                    onClicked: root.openCredentials(profileItem.modelData, false)
                  }

                  PanelActionButton {
                    visible: !profileItem.live && (profileItem.modelData.imported || profileItem.modelData.storedSecrets.length > 0 || profileItem.modelData.customName)
                    enabled: !actionProcess.running
                    iconText: "󰆴"
                    tooltipText: profileItem.confirmingForget ? "Click again to forget" : "Forget profile and credentials"
                    foreground: profileItem.confirmingForget ? root.urgent : root.foreground
                    fontFamily: root.fontFamily
                    Layout.alignment: Qt.AlignVCenter
                    onClicked: root.forget(profileItem.modelData)
                  }

                  PanelActionButton {
                    visible: profileItem.live
                    enabled: !profileItem.busy
                    iconText: "󰍃"
                    tooltipText: "Disconnect"
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    Layout.alignment: Qt.AlignVCenter
                    onClicked: root.runAction("disconnect", profileItem.modelData.path)
                  }
                }
              }
            }
          }

          Column {
            visible: root.renamePath !== ""
            width: parent.width
            spacing: Style.space(8)

            PanelSeparator { width: parent.width; foreground: root.foreground }
            PanelSectionHeader {
              text: "PROFILE NAME"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            TextField {
              id: profileNameField
              width: parent.width
              foreground: root.foreground
              placeholderText: "Profile name"
              text: root.renameText
              onTextChanged: root.renameText = text
              onAccepted: root.saveRename()
              Keys.onEscapePressed: root.closeRename()
            }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: "Save name"
                foreground: root.foreground
                fontFamily: root.fontFamily
                bordered: true
                enabled: !actionProcess.running
                onClicked: root.saveRename()
              }
              Button {
                text: "Cancel"
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.closeRename()
              }
            }
          }

          Column {
            visible: root.editPath !== ""
            width: parent.width
            spacing: Style.space(8)

            PanelSeparator { width: parent.width; foreground: root.foreground }
            PanelSectionHeader {
              text: (root.editFields.length === 1 && root.needs("cert-pass") ? "KEY PASSPHRASE · " : "CREDENTIALS · ") + root.editName.toUpperCase()
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            TextField {
              id: usernameField
              visible: root.needs("username")
              width: parent.width
              foreground: root.foreground
              placeholderText: "Username"
              text: root.usernameText
              onTextChanged: root.usernameText = text
              onAccepted: passwordField.forceActiveFocus()
              Keys.onEscapePressed: root.closeCredentials()
            }

            TextField {
              id: passwordField
              visible: root.needs("password")
              width: parent.width
              foreground: root.foreground
              placeholderText: "Password"
              password: true
              text: root.passwordText
              onTextChanged: root.passwordText = text
              onAccepted: root.needs("cert-pass") ? passphraseField.forceActiveFocus() : root.saveCredentials()
              Keys.onEscapePressed: root.closeCredentials()
            }

            TextField {
              id: passphraseField
              visible: root.needs("cert-pass")
              width: parent.width
              foreground: root.foreground
              placeholderText: "Private key passphrase"
              password: true
              text: root.passphraseText
              onTextChanged: root.passphraseText = text
              onAccepted: root.saveCredentials()
              Keys.onEscapePressed: root.closeCredentials()
            }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: root.connectAfterSave ? "Save and connect" : "Save to keyring"
                foreground: root.foreground
                fontFamily: root.fontFamily
                bordered: true
                enabled: !actionProcess.running
                onClicked: root.saveCredentials()
              }
              Button {
                text: "Cancel"
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.closeCredentials()
              }
            }
          }
        }
      }
    }
  }
}
