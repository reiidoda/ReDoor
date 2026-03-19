//
//  RedoorAppUITests.swift
//  RedoorAppUITests
//
//  Created by Rei Doda on 20/02/26.
//

import XCTest

final class RedoorAppUITests: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    override func tearDownWithError() throws {}

    @MainActor
    func testLaunchShowsHeroSymbolAndPrimaryAction() throws {
        let app = XCUIApplication()
        app.launch()

        XCTAssertTrue(
            app.otherElements["setup_hero_symbol"].waitForExistence(timeout: 5),
            "Setup hero symbol should be visible on launch"
        )

        let createIdentity = app.buttons["setup_create_identity_button"]
        let startSecureChat = app.buttons["setup_start_secure_chat_button"]

        XCTAssertTrue(
            createIdentity.waitForExistence(timeout: 2) || startSecureChat.waitForExistence(timeout: 2),
            "Setup should expose a primary action button"
        )
    }

    @MainActor
    func testSettingsScreenShowsSecurityActions() throws {
        let app = XCUIApplication()
        app.launch()

        let settingsButton = app.buttons["setup_settings_button"]
        XCTAssertFalse(settingsButton.exists, "Setup no longer exposes settings controls")
        XCTAssertTrue(app.staticTexts["SECURITY ENABLED"].waitForExistence(timeout: 5))
    }

    @MainActor
    func testGenerateIdentityTapShowsProgressOrNextStep() throws {
        let app = XCUIApplication()
        app.launch()

        let createIdentity = app.buttons["setup_create_identity_button"]
        let startSecureChat = app.buttons["setup_start_secure_chat_button"]

        if createIdentity.waitForExistence(timeout: 3) {
            XCTAssertTrue(createIdentity.isHittable, "Generate button should be tappable")
            createIdentity.tap()

            let status = app.otherElements["setup_status_message"]
            let generationFeedback = status.waitForExistence(timeout: 20)
            let movedForward = startSecureChat.waitForExistence(timeout: 20)

            XCTAssertTrue(
                generationFeedback || movedForward,
                "Tapping generate should show status feedback or advance to connect step"
            )
        } else {
            XCTAssertTrue(startSecureChat.waitForExistence(timeout: 5), "If identity already exists, app should be at connect step")
        }
    }

    @MainActor
    func testLaunchPerformance() throws {
        measure(metrics: [XCTApplicationLaunchMetric()]) {
            XCUIApplication().launch()
        }
    }
}
