package abstractfactories;

import strategyinterfaces.ModeStrategy;
import strategyinterfaces.PaddingStrategy;

public interface AbstractFactory {

	ModeStrategy getModeStrategy();

	PaddingStrategy getPaddingStrategy();
}
