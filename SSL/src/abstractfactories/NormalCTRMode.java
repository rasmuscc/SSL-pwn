package abstractfactories;

import modeOfOperations.CTRModeStrategy;
import strategyinterfaces.ModeStrategy;
import strategyinterfaces.PaddingStrategy;

public class NormalCTRMode implements AbstractFactory {

	@Override
	public ModeStrategy getModeStrategy() {
		return new CTRModeStrategy();
	}

	@Override
	public PaddingStrategy getPaddingStrategy() {
		return null;
	}
}
