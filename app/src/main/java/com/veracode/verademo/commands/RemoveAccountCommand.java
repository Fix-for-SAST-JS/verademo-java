package com.veracode.verademo.commands;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

public class RemoveAccountCommand implements BlabberCommand {
	private static final Logger logger = LogManager.getLogger("VeraDemo:RemoveAccountCommand");

	private Connection connect;

	public RemoveAccountCommand(Connection connect, String username) {
		super();
		this.connect = connect;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.veracode.verademo.commands.Command#execute()
	 */
	@Override
	public void execute(String blabberUsername) {
		String sqlQuery = "DELETE FROM listeners WHERE blabber=? OR listener=?;";
		logger.info(sqlQuery);
		PreparedStatement action;
		try {
			action = connect.prepareStatement(sqlQuery);

			action.setString(1, blabberUsername);
			action.setString(2, blabberUsername);
			action.execute();

			// Sanitize username for logging
			String safeUsername = URLEncoder.encode(blabberUsername, "UTF-8");

			sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
			try (PreparedStatement selectStmt = connect.prepareStatement(sqlQuery)) {
				logger.info("SELECT blab_name FROM users WHERE username = " + safeUsername);
				selectStmt.setString(1, blabberUsername);
				try (ResultSet result = selectStmt.executeQuery()) {
					result.next();

					/* START EXAMPLE VULNERABILITY */
					String event = "Removed account for blabber " + result.getString(1);
					sqlQuery = "INSERT INTO users_history (blabber, event) VALUES (?, ?)";
					try (PreparedStatement insertStmt = connect.prepareStatement(sqlQuery)) {
						logger.info("INSERT INTO users_history (blabber, event) VALUES (" + safeUsername + ", " + URLEncoder.encode(event, "UTF-8") + ")");
						insertStmt.setString(1, blabberUsername);
						insertStmt.setString(2, event);
						insertStmt.execute();
					}

					sqlQuery = "DELETE FROM users WHERE username = ?";
					try (PreparedStatement deleteStmt = connect.prepareStatement(sqlQuery)) {
						logger.info("DELETE FROM users WHERE username = " + safeUsername);
						deleteStmt.setString(1, blabberUsername);
						deleteStmt.execute();
					}
					/* END EXAMPLE VULNERABILITY */
				}
			}

		} catch (SQLException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}
}
